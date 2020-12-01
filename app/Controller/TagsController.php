<?php
App::uses('AppController', 'Controller');

/**
 * @property Tag $Tag
 */
class TagsController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'Tag.name' => 'asc'
            ),
            'contain' => array(
                'FavouriteTag',
                'Organisation' => array(
                    'fields' => array('id', 'name')
                )
            )
    );

    public $helpers = array('TextColour');

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->unlockedActions[] = 'search';
    }

    public function index()
    {
        $this->loadModel('Attribute');
        $this->loadModel('Event');
        $this->loadModel('Taxonomy');
        if ($this->_isSiteAdmin()) {
            $this->paginate['contain']['User'] = array('fields' => array('id', 'email'));
        }
        $filterData = array(
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'paramArray' => ['favouritesOnly', 'filter', 'searchall', 'name', 'search', 'exclude_statistics'],
            'ordered_url_params' => @compact($paramArray)
        );
        $exception = false;
        $passedArgsArray = $this->_harvestParameters($filterData, $exception);

        $this->Event->recursive = -1;
        if (!empty($passedArgsArray['favouritesOnly'])) {
            $tag_id_list = $this->Tag->FavouriteTag->find('list', array(
                    'conditions' => array('FavouriteTag.user_id' => $this->Auth->user('id')),
                    'fields' => array('FavouriteTag.tag_id')
            ));
            if (empty($tag_id_list)) {
                $tag_id_list = array(-1);
            }
            $this->paginate['conditions']['AND']['Tag.id'] = $tag_id_list;
        }
        if (!empty($passedArgsArray['searchall'])) {
            $this->paginate['conditions']['AND'][] = ['LOWER(Tag.name) LIKE' => '%' . strtolower($passedArgsArray['searchall']) . '%'];
        }
        foreach (['name', 'filter', 'search'] as $f) {
            if (!empty($passedArgsArray['name'])) {
                $this->paginate['conditions']['AND'][] = ['LOWER(Tag.name)' => strtolower($passedArgsArray[$f])];
            }
        }
        if ($this->_isRest()) {
            unset($this->paginate['limit']);
            $paginated = $this->Tag->find('all', $this->paginate);
        } else {
            $paginated = $this->paginate();
        }
        $tagList = array();
        $taxonomyTags = array();
        $taxonomyNamespaces = $this->Taxonomy->listTaxonomies(array('full' => false, 'enabled' => true));
        foreach ($paginated as $k => $tag) {
            $tagList[] = $tag['Tag']['id'];
            $favourite = false;
            if (!empty($tag['FavouriteTag'])) {
                foreach ($tag['FavouriteTag'] as $ft) {
                    if ($ft['user_id'] == $this->Auth->user('id')) {
                        $favourite = true;
                        break;
                    }
                }
            }
            $paginated[$k]['Tag']['favourite'] = $favourite;
            unset($paginated[$k]['FavouriteTag']);

            foreach ($taxonomyNamespaces as $namespace => $taxonomy) {
                if (substr(strtoupper($tag['Tag']['name']), 0, strlen($namespace)) === strtoupper($namespace)) {
                    $paginated[$k]['Tag']['Taxonomy'] = $taxonomy;
                    if (!isset($taxonomyTags[$namespace])) {
                        $taxonomyTags[$namespace] = $this->Taxonomy->getTaxonomyTags($taxonomy['id'], true);
                    }
                    $paginated[$k]['Tag']['Taxonomy']['expanded'] = isset($taxonomyTags[$namespace][strtoupper($tag['Tag']['name'])]) ? $taxonomyTags[$namespace][strtoupper($tag['Tag']['name'])] : $tag['Tag']['name'];
                    break;
                }
            }
        }

        if (empty($passedArgsArray['exclude_statistics'])) {
            $attributeCount = $this->Tag->AttributeTag->countForTags($tagList, $this->Auth->user());
            // TODO: this must be called before `tagsSparkline`!
            $eventCount = $this->Tag->EventTag->countForTags($tagList, $this->Auth->user());

            if ($this->_isRest()) {
                $csvForTags = []; // Sightings sparkline doesn't make sense for REST requests
            } else {
                $this->loadModel('Sighting');
                $csvForTags = $this->Sighting->tagsSparkline($tagList, $this->Auth->user(), '0');
            }
            foreach ($paginated as $k => $tag) {
                $tagId = $tag['Tag']['id'];
                if (isset($csvForTags[$tagId])) {
                    $paginated[$k]['Tag']['csv'] = $csvForTags[$tagId];
                }
                $paginated[$k]['Tag']['count'] = isset($eventCount[$tagId]) ? (int)$eventCount[$tagId] : 0;
                $paginated[$k]['Tag']['attribute_count'] = isset($attributeCount[$tagId]) ? (int)$attributeCount[$tagId] : 0;
            }
        } else {
            $this->set('exclude_statistics', true);
        }

        if ($this->_isRest()) {
            foreach ($paginated as $key => $tag) {
                $paginated[$key] = $tag['Tag'];
            }
            $this->set('Tag', $paginated);
            $this->set('_serialize', array('Tag'));
        } else {
            $this->set('passedArgs', json_encode($this->passedArgs));
            $this->set('passedArgsArray', $passedArgsArray);
            $this->set('list', $paginated);
            $this->set('favouritesOnly', !empty($passedArgsArray['favouritesOnly']));
        }
        // send perm_tagger to view for action buttons
    }

    public function add()
    {
        if (!$this->_isSiteAdmin() && !$this->userRole['perm_tag_editor']) {
            throw new NotFoundException('You don\'t have permission to do that.');
        }
        if ($this->request->is('post')) {
            if (!isset($this->request->data['Tag'])) {
                $this->request->data = array('Tag' => $this->request->data);
            }
            if (isset($this->request->data['Tag']['request'])) {
                $this->request->data['Tag'] = $this->request->data['Tag']['request'];
            }
            if (!isset($this->request->data['Tag']['colour'])) {
                $this->request->data['Tag']['colour'] = $this->Tag->random_color();
            }
            if (isset($this->request->data['Tag']['id'])) {
                unset($this->request->data['Tag']['id']);
            }
            if ($this->_isRest()) {
                $tag = $this->Tag->find('first', array(
                    'conditions' => array(
                        'Tag.name' => $this->request->data['Tag']['name']
                    ),
                    'recursive' => -1
                ));
                if (!empty($tag)) {
                    return $this->RestResponse->viewData($tag, $this->response->type());
                }
            }
            if ($this->Tag->save($this->request->data)) {
                if ($this->_isRest()) {
                    $tag = $this->Tag->find('first', array(
                        'conditions' => array(
                            'Tag.id' => $this->Tag->id
                        ),
                        'recursive' => -1
                    ));
                    return $this->RestResponse->viewData($tag, $this->response->type());
                }
                $this->Flash->success('The tag has been saved.');
                $this->redirect(array('action' => 'index'));
            } else {
                if ($this->_isRest()) {
                    $error_message = '';
                    foreach ($this->Tag->validationErrors as $k => $v) {
                        $error_message .= '[' . $k . ']: ' . $v[0];
                    }
                    throw new MethodNotAllowedException('Could not add the Tag. ' . $error_message);
                } else {
                    $this->Flash->error('The tag could not be saved. Please, try again.');
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('Tag', 'add', false, $this->response->type());
        }
        $this->loadModel('Organisation');
        $temp = $this->Organisation->find('all', array(
            'conditions' => array('local' => 1),
            'fields' => array('id', 'name'),
            'recursive' => -1
        ));
        $orgs = array(0 => 'Unrestricted');
        if (!empty($temp)) {
            foreach ($temp as $org) {
                $orgs[$org['Organisation']['id']] = $org['Organisation']['name'];
            }
        }
        $this->set('orgs', $orgs);
        $users = array(0 => 'Unrestricted');
        if ($this->_isSiteAdmin()) {
            $temp = $this->Organisation->User->find('all', array(
                'conditions' => array('disabled' => 0),
                'fields' => array('id', 'email'),
                'recursive' => -1
            ));
            if (!empty($temp)) {
                foreach ($temp as $user) {
                    $users[$user['User']['id']] = $user['User']['email'];
                }
            }
            $this->set('users', $users);
        }
    }

    public function quickAdd()
    {
        if ((!$this->_isSiteAdmin() && !$this->userRole['perm_tag_editor']) || !$this->request->is('post')) {
            throw new NotFoundException('You don\'t have permission to do that.');
        }
        if (isset($this->request->data['Tag']['request'])) {
            $this->request->data['Tag'] = $this->request->data['Tag']['request'];
        }
        if ($this->Tag->quickAdd($this->request->data['Tag']['name'])) {
            $this->Flash->success('The tag has been saved.');
        } else {
            $this->Flash->error('The tag could not be saved. Please, try again.');
        }
        $this->redirect($this->referer());
    }

    public function edit($id = false)
    {
        if ($id === false && (!$this->_isRest() || !$this->request->is('get'))) {
            throw new NotFoundException('No ID set.');
        } elseif (!empty($id)) {
            $this->Tag->id = $id;
            if (!$this->Tag->exists()) {
                throw new NotFoundException('Invalid tag');
            }
        }
        if (!$this->_isSiteAdmin()) {
            throw new NotFoundException('You don\'t have permission to do that.');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['Tag'])) {
                $this->request->data = array('Tag' => $this->request->data);
            }
            $this->request->data['Tag']['id'] = $id;
            if ($this->Tag->save($this->request->data)) {
                if ($this->_isRest()) {
                    $tag = $this->Tag->find('first', array(
                        'conditions' => array(
                            'Tag.id' => $id
                        ),
                        'recursive' => -1
                    ));
                    return $this->RestResponse->viewData($tag, $this->response->type());
                }
                $this->Flash->success('The Tag has been edited');
                $this->redirect(array('action' => 'index'));
            } else {
                if ($this->_isRest()) {
                    $error_message = '';
                    foreach ($this->Tag->validationErrors as $k => $v) {
                        $error_message .= '[' . $k . ']: ' . $v[0];
                    }
                    throw new MethodNotAllowedException('Could not add the Tag. ' . $error_message);
                }
                $this->Flash->error('The Tag could not be saved. Please, try again.');
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('Tag', 'edit', false, $this->response->type());
        }
        $this->loadModel('Organisation');
        $temp = $this->Organisation->find('all', array(
            'conditions' => array('local' => 1),
            'fields' => array('id', 'name'),
            'recursive' => -1
        ));
        $orgs = array(0 => 'Unrestricted');
        if (!empty($temp)) {
            foreach ($temp as $org) {
                $orgs[$org['Organisation']['id']] = $org['Organisation']['name'];
            }
        }
        $this->set('orgs', $orgs);
        $users = array(0 => 'Unrestricted');
        if ($this->_isSiteAdmin()) {
            $temp = $this->Organisation->User->find('all', array(
                'conditions' => array('disabled' => 0),
                'fields' => array('id', 'email'),
                'recursive' => -1
            ));
            if (!empty($temp)) {
                foreach ($temp as $user) {
                    $users[$user['User']['id']] = $user['User']['email'];
                }
            }
            $this->set('users', $users);
        }
        $this->request->data = $this->Tag->read(null, $id);
    }

    public function delete($id)
    {
        if (!$this->_isSiteAdmin()) {
            throw new NotFoundException('You don\'t have permission to do that.');
        }
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->Tag->id = $id;
        if (!$this->Tag->exists()) {
            throw new NotFoundException('Invalid tag');
        }
        if ($this->Tag->delete()) {
            if ($this->_isRest()) {
                $this->set('name', 'Tag deleted.');
                $this->set('message', 'Tag deleted.');
                $this->set('url', $this->baseurl . '/tags/delete/' . $id);
                $this->set('_serialize', array('name', 'message', 'url'));
            }
            $this->Flash->success(__('Tag deleted'));
        } else {
            if ($this->_isRest()) {
                throw new MethodNotAllowedException('Could not delete the tag, or tag doesn\'t exist.');
            }
            $this->Flash->error(__('Tag was not deleted'));
        }
        if (!$this->_isRest()) {
            $this->redirect(array('action' => 'index'));
        }
    }

    public function view($id)
    {
        if ($this->_isRest()) {
            $contain = array('EventTag' => array('fields' => 'event_id'));
            $contain['AttributeTag'] = array('fields' => 'attribute_id');
            $tag = $this->Tag->find('first', array(
                    'conditions' => array('id' => $id),
                    'recursive' => -1,
                    'contain' => $contain
            ));
            if (empty($tag)) {
                throw new MethodNotAllowedException('Invalid Tag');
            }
            if (empty($tag['EventTag'])) {
                $tag['Tag']['count'] = 0;
            } else {
                $eventIDs = array();
                foreach ($tag['EventTag'] as $eventTag) {
                    $eventIDs[] = $eventTag['event_id'];
                }
                $conditions = array('Event.id' => $eventIDs);
                if (!$this->_isSiteAdmin()) {
                    $conditions = array_merge(
                        $conditions,
                        array('OR' => array(
                                array('AND' => array(
                                        array('Event.distribution >' => 0),
                                        array('Event.published =' => 1)
                                )),
                                array('Event.orgc_id' => $this->Auth->user('org_id'))
                        ))
                );
                }
                $events = $this->Tag->EventTag->Event->find('all', array(
                        'fields' => array('Event.id', 'Event.distribution', 'Event.orgc_id'),
                        'conditions' => $conditions
                ));
                $tag['Tag']['count'] = count($events);
            }
            unset($tag['EventTag']);
            if (empty($tag['AttributeTag'])) {
                $tag['Tag']['attribute_count'] = 0;
            } else {
                $attributeIDs = array();
                foreach ($tag['AttributeTag'] as $attributeTag) {
                    $attributeIDs[] = $attributeTag['attribute_id'];
                }
                $conditions = array('Attribute.id' => $attributeIDs);
                if (!$this->_isSiteAdmin()) {
                    $conditions = array_merge(
                        $conditions,
                        array('OR' => array(
                            array('AND' => array(
                                array('Attribute.deleted =' => 0),
                                array('Attribute.distribution >' => 0),
                                array('Event.distribution >' => 0),
                                array('Event.published =' => 1)
                            )),
                            array('Event.orgc_id' => $this->Auth->user('org_id'))
                        ))
                    );
                }
                $attributes = $this->Tag->AttributeTag->Attribute->find('all', array(
                    'fields'     => array('Attribute.id', 'Attribute.deleted', 'Attribute.distribution', 'Event.id', 'Event.distribution', 'Event.orgc_id'),
                    'contain'    => array('Event' => array('fields' => array('id', 'distribution', 'orgc_id'))),
                    'conditions' => $conditions
                ));
                $tag['Tag']['attribute_count'] = count($attributes);
            }
            unset($tag['AttributeTag']);
            $this->set('Tag', $tag['Tag']);
            $this->set('_serialize', 'Tag');
        } else {
            throw new MethodNotAllowedException('This action is only for REST users.');
        }
    }

    public function showEventTag($id)
    {
        $this->loadModel('Taxonomy');

        $event = $this->Tag->EventTag->Event->fetchSimpleEvent($this->Auth->user(), $id, [
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.user_id'],
            'contain' => [
                'EventTag' => array(
                    'Tag' => array('order' => false),
                    'order' => false
                )
            ],
        ]);
        if (!$event) {
            throw new NotFoundException(__('Invalid event.'));
        }
        // Remove galaxy tags
        $event = $this->Tag->EventTag->Event->massageTags($this->Auth->user(), $event, 'Event', false, true);

        $this->set('tags', $event['EventTag']);
        $this->set('required_taxonomies', $this->Tag->EventTag->Event->getRequiredTaxonomies());
        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($event['EventTag']);
        $this->set('tagConflicts', $tagConflicts);
        $this->set('event', $event);
        $this->layout = 'ajax';
        $this->render('/Events/ajax/ajaxTags');
    }

    public function showAttributeTag($id)
    {
        $this->helpers[] = 'TextColour';
        $this->loadModel('Attribute');
        $this->loadModel('Taxonomy');

        $attributes = $this->Attribute->fetchAttributes($this->Auth->user(), [
            'conditions' => ['Attribute.id' => $id],
            'includeAllTags' => true,
            'flatten' => true,
            'contain' => array(
                'Event',
            ),
        ]);
        if (empty($attributes)) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $attribute = $attributes[0];
        // Remove galaxy tags
        $attribute = $this->Tag->EventTag->Event->massageTags($this->Auth->user(), $attribute, 'Attribute', false, true);
        $attributeTags = $attribute['AttributeTag'];

        $this->set('event', ['Event' => $attribute['Event']]);
        $this->set('attributeTags', $attributeTags);
        $this->set('attributeId', $id);
        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attributeTags);
        $this->set('tagConflicts', $tagConflicts);
        $this->layout = 'ajax';
        $this->render('/Attributes/ajax/ajaxAttributeTags');
    }

    public function showTagControllerTag($id)
    {
        $this->loadModel('TagCollection');
        $tagCollection = $this->TagCollection->find('first', array(
            'recursive' => -1,
            'contain' => array('TagCollection'),
            'conditions' => array('TagCollection.id' => $id)
        ));
        if (empty($tagCollection) || (!$this->_isSiteAdmin() && $tagCollection['org_id'] !== $this->Auth->user('org_id'))) {
            throw new MethodNotAllowedException('Invalid tag_collection.');
        }
        $this->loadModel('GalaxyCluster');
        $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.id', 'GalaxyCluster.tag_name')));
        $this->helpers[] = 'TextColour';
        $tags = $this->TagCollection->TagCollectionTag->find('all', array(
                'conditions' => array(
                        'tag_collection_id' => $id,
                        'Tag.name !=' => $cluster_names
                ),
                'contain' => array('Tag'),
                'fields' => array('Tag.id', 'Tag.colour', 'Tag.name'),
        ));
        $this->set('tags', $tags);
        $event = $this->Tag->EventTag->Event->find('first', array(
                'recursive' => -1,
                'fields' => array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.user_id'),
                'conditions' => array('Event.id' => $id)
        ));
        $this->set('event', $event);
        $this->layout = 'ajax';
        $this->render('/Events/ajax/ajaxTags');
    }

    public function viewTag($id)
    {
        $tag = $this->Tag->find('first', array(
                'conditions' => array(
                        'id' => $id
                ),
                'recursive' => -1,
        ));
        $this->layout = null;
        $this->set('tag', $tag);
        $this->set('id', $id);
        $this->render('ajax/view_tag');
    }


    public function selectTaxonomy($id, $scope = 'event')
    {
        if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) {
            throw new NotFoundException('You don\'t have permission to do that.');
        }
        $localFlag = !empty($this->params['named']['local']) ? '/local:1' : '';
        $items = array();
        $favourites = $this->Tag->FavouriteTag->find('count', array('conditions' => array('FavouriteTag.user_id' => $this->Auth->user('id'))));
        if ($favourites) {
            $items[] = array(
                'name' => __('Favourite Tags'),
                'value' => $this->baseurl . "/tags/selectTag/" . h($id) . "/favourites/" . h($scope) . $localFlag
            );
        }
        if ($scope !== 'tag_collection') {
            $items[] = array(
                'name' => __('Tag Collections'),
                'value' => $this->baseurl . "/tags/selectTag/" . h($id) . "/collections/" . h($scope) . $localFlag
            );
        }
        $items[] = array(
            'name' => __('Custom Tags'),
            'value' => $this->baseurl . "/tags/selectTag/" . h($id) . "/0/" . h($scope) . $localFlag
        );
        $items[] = array(
            'name' => __('All Tags'),
            'value' => $this->baseurl . "/tags/selectTag/" . h($id) . "/all/" . h($scope) . $localFlag
        );

        $this->loadModel('Taxonomy');
        $options = $this->Taxonomy->find('list', array('conditions' => array('enabled' => true), 'fields' => array('namespace'), 'order' => array('Taxonomy.namespace ASC')));
        foreach ($options as $k => $option) {
            $items[] = array(
                'name' => __('Taxonomy Library') . ":" . h($option),
                'value' => $this->baseurl . "/tags/selectTag/" . h($id) . "/" . h($k) . "/" . h($scope . $localFlag)
            );
        }
        $this->set('items', $items);
        $this->set('options', array( // set chosen (select picker) options
            'select_options' => array(
                'multiple' => 0,
            )
        ));
        $this->render('/Elements/generic_picker');
    }

    public function selectTag($id, $taxonomy_id, $scope = 'event', $filterData = '')
    {
        if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) {
            throw new NotFoundException('You don\'t have permission to do that.');
        }
        $this->loadModel('Taxonomy');
        $expanded = array();
        $this->set('taxonomy_id', $taxonomy_id);
        if ($taxonomy_id === 'collections') {
            $this->loadModel('TagCollection');
            // This method removes banned and hidden tags
            $tagCollections = $this->TagCollection->fetchTagCollection($this->Auth->user());
            $tags = array();
            $inludedTagListString = array();
            $expanded = array();
            foreach ($tagCollections as &$tagCollection) {
                $tags[$tagCollection['TagCollection']['id']] = $tagCollection['TagCollection'];
                $expanded[$tagCollection['TagCollection']['id']] = empty($tagCollection['TagCollection']['description']) ? $tagCollection['TagCollection']['name'] : $tagCollection['TagCollection']['description'];
                if (!empty($tagCollection['TagCollectionTag'])) {
                    $tagList = array();
                    foreach ($tagCollection['TagCollectionTag'] as $tce) {
                        $tagList[] = $tce['Tag']['name'];
                        $tagCollection['TagCollectionTag'] = array_values($tagCollection['TagCollectionTag']);
                    }
                    $tagList = implode(', ', $tagList);
                    $inludedTagListString[$tagCollection['TagCollection']['id']] = $tagList;
                    $expanded[$tagCollection['TagCollection']['id']] .= sprintf(' (%s)', $tagList);
                }
            }
        } else {
            if ($taxonomy_id === '0') {
                $temp = $this->Taxonomy->getAllTaxonomyTags(true, $this->Auth->user(), true);
                $tags = array();
                foreach ($temp as $tag) {
                    $tags[$tag['Tag']['id']] = $tag['Tag'];
                }
                unset($temp);
                $expanded = $tags;
            } elseif ($taxonomy_id === 'favourites') {
                $tags = array();
                $conditions = array(
                    'FavouriteTag.user_id' => $this->Auth->user('id'),
                    'Tag.org_id' => array(0, $this->Auth->user('org_id')),
                    'Tag.user_id' => array(0, $this->Auth->user('id')),
                    'Tag.hide_tag' => 0,
                );
                $favTags = $this->Tag->FavouriteTag->find('all', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                    'contain' => array('Tag'),
                    'order' => array('Tag.name asc')
                ));
                foreach ($favTags as $favTag) {
                    $tags[$favTag['FavouriteTag']['tag_id']] = $favTag['Tag'];
                    $expanded = $tags;
                }
            } elseif ($taxonomy_id === 'all') {
                $conditions = [];
                if (!$this->_isSiteAdmin()) {
                    $conditions[] = array('Tag.org_id' => array(0, $this->Auth->user('org_id')));
                    $conditions[] = array('Tag.user_id' => array(0, $this->Auth->user('id')));
                }
                $conditions['Tag.hide_tag'] = 0;
                $allTags = $this->Tag->find('all', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                    'order' => array('name asc'),
                    'fields' => array('Tag.id', 'Tag.name', 'Tag.colour')
                ));
                $tags = array();
                foreach ($allTags as $tag) {
                    $isGalaxyTag = strpos($tag['Tag']['name'], 'misp-galaxy:') === 0;
                    if (!$isGalaxyTag) {
                        $tags[$tag['Tag']['id']] = $tag['Tag'];
                    }
                }
                unset($allTags);
                $expanded = $tags;
            } else {
                $taxonomies = $this->Taxonomy->getTaxonomy($taxonomy_id);
                $tags = array();
                if (!empty($taxonomies['entries'])) {
                    foreach ($taxonomies['entries'] as $entry) {
                        if (!empty($entry['existing_tag']['Tag'])) {
                            $tags[$entry['existing_tag']['Tag']['id']] = $entry['existing_tag']['Tag'];
                            $expanded[$entry['existing_tag']['Tag']['id']] = $entry['expanded'];
                        }
                    }
                }

                // Unset all tags that this user cannot use for tagging, determined by the org restriction on tags
                if (!$this->_isSiteAdmin()) {
                    $banned_tags = $this->Tag->find('list', array(
                        'conditions' => array(
                            'NOT' => array(
                                'Tag.org_id' => array(
                                    0,
                                    $this->Auth->user('org_id')
                                ),
                                'Tag.user_id' => array(
                                    0,
                                    $this->Auth->user('id')
                                )
                            )
                        ),
                        'fields' => array('Tag.id')
                    ));
                    foreach ($banned_tags as $banned_tag) {
                        unset($tags[$banned_tag]);
                        unset($expanded[$banned_tag]);
                    }
                }

                $hidden_tags = $this->Tag->find('list', array(
                    'conditions' => array('Tag.hide_tag' => 1),
                    'fields' => array('Tag.id')
                ));
                foreach ($hidden_tags as $hidden_tag) {
                    unset($tags[$hidden_tag]);
                    unset($expanded[$hidden_tag]);
                }
            }
        }

        $this->set('scope', $scope);
        $this->set('object_id', $id);

        if ($scope === 'attribute') {
            $onClickForm = 'quickSubmitAttributeTagForm';
        } elseif ($scope === 'tag_collection') {
            $onClickForm = 'quickSubmitTagCollectionTagForm';
        } else {
            $onClickForm = 'quickSubmitTagForm';
        }
        $items = array();
        foreach ($tags as $k => $tag) {
            $tagName = $tag['name'];
            $choice_id = $k;
            if ($taxonomy_id === 'collections') {
                $choice_id = 'collection_' . $choice_id;
            }

            $itemParam = array(
                'name' => $tagName,
                'value' => $choice_id,
                'template' => array(
                    'name' => array(
                        'name' => $tagName,
                        'label' => array(
                            'background' => isset($tag['colour']) ? $tag['colour'] : '#ffffff'
                        )
                    ),
                    'infoExtra' => $expanded[$tag['id']]
                ),
                'additionalData' => array(
                    'tag_name' => $tagName
                )
            );
            if ($taxonomy_id === 'collections') {
                $itemParam['template']['infoContextual'] = __('Includes: ') . $inludedTagListString[$tag['id']];
            }
            $items[] = $itemParam;
        }
        $this->set('items', $items);
        $this->set('options', array( // set chosen (select picker) options
            'functionName' => $onClickForm,
            'multiple' => -1,
            'select_options' => array(
                'additionalData' => array(
                    'id' => $id,
                    'local' => !empty($this->params['named']['local'])
                ),
            ),
        ));
        $this->set('local', !empty($this->params['named']['local']));
        $this->render('ajax/select_tag');
    }

    public function tagStatistics($percentage = false, $keysort = false)
    {
        $result = $this->Tag->EventTag->find('all', array(
                'recursive' => -1,
                'fields' => array('count(EventTag.id) as count', 'tag_id'),
                'contain' => array('Tag' => array('fields' => array('Tag.name'))),
                'group' => array('tag_id')
        ));
        $tags = array();
        $taxonomies = array();
        $totalCount = 0;
        $this->loadModel('Taxonomy');
        $temp = $this->Taxonomy->listTaxonomies(array('enabled' => true));
        foreach ($temp as $t) {
            if ($t['enabled']) {
                $taxonomies[$t['namespace']] = 0;
            }
        }
        foreach ($result as $r) {
            if ($r['Tag']['name'] == null) {
                continue;
            }
            $tags[$r['Tag']['name']] = $r[0]['count'];
            $totalCount += $r[0]['count'];
            foreach ($taxonomies as $taxonomy => $count) {
                if (substr(strtolower($r['Tag']['name']), 0, strlen($taxonomy)) === strtolower($taxonomy)) {
                    $taxonomies[$taxonomy] += $r[0]['count'];
                }
            }
        }
        if ($keysort === 'true') {
            ksort($tags, SORT_NATURAL | SORT_FLAG_CASE);
            ksort($taxonomies, SORT_NATURAL | SORT_FLAG_CASE);
        } else {
            arsort($tags);
            arsort($taxonomies);
        }
        if ($percentage === 'true') {
            foreach ($tags as $tag => $count) {
                $tags[$tag] = round(100 * $count / $totalCount, 3) . '%';
            }
            foreach ($taxonomies as $taxonomy => $count) {
                $taxonomies[$taxonomy] = round(100 * $count / $totalCount, 3) . '%';
            }
        }
        $results = array('tags' => $tags, 'taxonomies' => $taxonomies);
        $this->autoRender = false;
        $this->layout = false;
        $this->set('data', $results);
        $this->set('flags', JSON_PRETTY_PRINT);
        $this->response->type('json');
        $this->render('/Servers/json/simple');
    }

    private function __findObjectByUuid($object_uuid, &$type, $scope = 'modify')
    {
        $this->loadModel('Event');
        if (!$this->userRole['perm_tagger']) {
            throw new MethodNotAllowedException(__('This functionality requires tagging permission.'));
        }
        $object = $this->Event->fetchEvent($this->Auth->user(), array(
            'event_uuid' => $object_uuid,
            'metadata' => 1
        ));
        $type = 'Event';
        if (!empty($object)) {
            $object = $object[0];
            if (
                $scope !== 'view' &&
                !$this->_isSiteAdmin() &&
                $object['Event']['orgc_id'] != $this->Auth->user('org_id')
            ) {
                $message = __('Cannot alter the tags of this data, only the organisation that has created the data (orgc) can modify global tags.');
                if ($this->Auth->user('org_id') === Configure::read('MISP.host_org_id')) {
                    $message .= ' ' . __('Please consider using local tags if you are in the host organisation of the instance.');
                }
                throw new MethodNotAllowedException($message);
            }
        } else {
            $type = 'Attribute';
            $object = $this->Event->Attribute->fetchAttributes(
                $this->Auth->user(),
                array(
                    'conditions' => array(
                        'Attribute.uuid' => $object_uuid
                    ),
                    'flatten' => 1
                )
            );
            if (!empty($object)) {
                $object = $object[0];
                if (
                    $scope !== 'view' &&
                    !$this->_isSiteAdmin() &&
                    $object['Event']['orgc_id'] != $this->Auth->user('org_id')
                ) {
                    $message = __('Cannot alter the tags of this data, only the organisation that has created the data (orgc) can modify global tags.');
                    if ($this->Auth->user('org_id') === Configure::read('MISP.host_org_id')) {
                        $message .= ' ' . __('Please consider using local tags if you are in the host organisation of the instance.');
                    }
                    throw new MethodNotAllowedException($message);
                }
            } else {
                throw new MethodNotAllowedException(__('Invalid Target.'));
            }
        }
        return $object;
    }

    public function attachTagToObject($uuid = false, $tags = false, $local = false)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This method is only accessible via POST requests.');
        }
        if (empty($uuid)) {
            if (!empty($this->request->data['uuid'])) {
                $uuid = $this->request->data['uuid'];
            } else {
                throw new MethodNotAllowedException('Invalid object uuid');
            }
        }
        if (!Validation::uuid($uuid)) {
            throw new InvalidArgumentException('Invalid UUID');
        }
        if (empty($tags)) {
            if (!empty($this->request->data['tag'])) {
                $tags = $this->request->data['tag'];
            } else {
                throw new MethodNotAllowedException('Invalid tag');
            }
        }
        if (!is_array($tags)) {
            $tags = array($tags);
        }
        $successes = 0;
        $fails = array();
        foreach ($tags as $k => $tag) {
            if (is_numeric($tag)) {
                $conditions = array('Tag.id' => $tag);
            } else {
                $conditions = array('Tag.name LIKE' => trim($tag));
            }
            if (empty($local)) {
                if (!empty($this->request->data['local'])) {
                    $local = $this->request->data['local'];
                }
            }
            if (!empty($local) && $this->Auth->user('org_id') != Configure::read('MISP.host_org_id')) {
                $fails[] = __('Local tags can only be added by users of the host organisation.');
                continue;
            }
            $objectType = '';
            $object = $this->__findObjectByUuid($uuid, $objectType, $local ? 'view' : 'modify');
            $existingTag = $this->Tag->find('first', array('conditions' => $conditions, 'recursive' => -1));
            if (empty($existingTag)) {
                if (!is_numeric($tag)) {
                    if (!$this->userRole['perm_tag_editor']) {
                        $fails[] = __('Tag not found and insufficient privileges to create it.');
                        continue;
                    }
                    $this->Tag->create();
                    $result = $this->Tag->save(array('Tag' => array('name' => $tag, 'colour' => $this->Tag->random_color())));
                    if (!$result) {
                        $fails[] = __('Unable to create tag. Reason: ' . json_encode($this->Tag->validationErrors));
                        continue;
                    }
                    $existingTag = $this->Tag->find('first', array('recursive' => -1, 'conditions' => array('Tag.id' => $this->Tag->id)));
                } else {
                    $fails[] = __('Invalid Tag.');
                    continue;
                }
            }
            if (!$this->_isSiteAdmin()) {
                if (!in_array($existingTag['Tag']['org_id'], array(0, $this->Auth->user('org_id')))) {
                    $fails[] = __('Invalid Tag. This tag can only be set by a fixed organisation.');
                    continue;
                }
                if (!in_array($existingTag['Tag']['user_id'], array(0, $this->Auth->user('id')))) {
                    $fails[] = __('Invalid Tag. This tag can only be set by a fixed user.');
                    continue;
                }
            }
            $this->loadModel($objectType);
            $connectorObject = $objectType . 'Tag';
            $conditions = array(
                strtolower($objectType) . '_id' => $object[$objectType]['id'],
                'tag_id' => $existingTag['Tag']['id'],
                'local' => ($local ? 1 : 0)
            );
            $existingAssociation = $this->$objectType->$connectorObject->find('first', array(
                'conditions' => $conditions
            ));
            if (!empty($existingAssociation)) {
                $fails[] = __('%s already has the requested tag attached, no changes had to be made.', $objectType);
                continue;
            }
            $this->$objectType->$connectorObject->create();
            $data = array(
                $connectorObject => $conditions
            );
            if ($objectType == 'Attribute') {
                $data[$connectorObject]['event_id'] = $object['Event']['id'];
            }
            $result = $this->$objectType->$connectorObject->save($data);
            if ($result) {
                $tempObject = $this->$objectType->find('first', array(
                    'recursive' => -1,
                    'conditions' => array($objectType . '.id' => $object[$objectType]['id'])
                ));
                $date = new DateTime();
                $tempObject[$objectType]['timestamp'] = $date->getTimestamp();
                $this->$objectType->save($tempObject);
                if ($local) {
                    $message = 'Local tag ' . $existingTag['Tag']['name'] . '(' . $existingTag['Tag']['id'] . ') successfully attached to ' . $objectType . '(' . $object[$objectType]['id'] . ').';
                } else {
                    if ($objectType === 'Attribute') {
                        $this->$objectType->Event->unpublishEvent($object['Event']['id']);
                    } elseif ($objectType === 'Event') {
                        $this->Event->unpublishEvent($object['Event']['id']);
                    }
                    $message = 'Global tag ' . $existingTag['Tag']['name'] . '(' . $existingTag['Tag']['id'] . ') successfully attached to ' . $objectType . '(' . $object[$objectType]['id'] . ').';
                }
                $successes++;
            } else {
                $fails[] = __('Failed to attach tag to object.');
            }
        }
        if (!empty($fails)) {
            $failedMessage = __('Failed to attach %s tags. Reasons: %s', count($fails), json_encode($fails,  JSON_FORCE_OBJECT));
        }
        if ($successes > 0) {
            $message = __('Successfully attached %s tags to %s (%s)', $successes, $objectType, $object[$objectType]['id']);
            $message .= !empty($fails) ? PHP_EOL . $failedMessage : '';
            return $this->RestResponse->saveSuccessResponse('Tags', 'attachTagToObject', false, $this->response->type(), $message);
        } else {
            return $this->RestResponse->saveFailResponse('Tags', 'attachTagToObject', false, $failedMessage, $this->response->type());
        }
    }

    public function removeTagFromObject($uuid = false, $tag = false)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This method is only accessible via POST requests.');
        }
        if (empty($uuid)) {
            if (!empty($this->request->data['uuid'])) {
                $uuid = $this->request->data['uuid'];
            } else {
                throw new MethodNotAllowedException('Invalid object uuid');
            }
        }
        if (!Validation::uuid($uuid)) {
            throw new InvalidArgumentException('Invalid UUID');
        }
        if (empty($tag)) {
            if (!empty($this->request->data['tag'])) {
                $tag = $this->request->data['tag'];
            } else {
                throw new MethodNotAllowedException('Invalid tag');
            }
        }
        if (is_numeric($tag)) {
            $conditions = array('Tag.id' => $tag);
        } else {
            $conditions = array('LOWER(Tag.name) LIKE' => strtolower(trim($tag)));
        }
        $existingTag = $this->Tag->find('first', array('conditions' => $conditions, 'recursive' => -1));
        if (empty($existingTag)) {
            throw new MethodNotAllowedException('Invalid Tag.');
        }
        $objectType = '';
        $object = $this->__findObjectByUuid($uuid, $objectType, 'view');
        if (empty($object)) {
            throw new MethodNotAllowedException(__('Invalid Target.'));
        }
        $connectorObject = $objectType . 'Tag';
        $this->loadModel($objectType);
        $existingAssociation = $this->$objectType->$connectorObject->find('first', array(
            'conditions' => array(
                strtolower($objectType) . '_id' => $object[$objectType]['id'],
                'tag_id' => $existingTag['Tag']['id']
            )
        ));
        if (empty($existingAssociation)) {
            throw new MethodNotAllowedException('Could not remove tag as it is not attached to the target ' . $objectType);
        } else {
            if (empty($existingAssociation[$objectType . 'Tag']['local'])) {
                $object = $this->__findObjectByUuid($uuid, $objectType);
            } else {
                if ($object['Event']['orgc_id'] !== $this->Auth->user('org_id') && $this->Auth->user('org_id') != Configure::read('MISP.host_org_id')) {
                    throw new MethodNotAllowedException(__('Insufficient privileges to remove local tags from events you do not own.'));
                }
            }
        }
        $result = $this->$objectType->$connectorObject->delete($existingAssociation[$connectorObject]['id']);
        if ($result) {
            $message = 'Tag ' . $existingTag['Tag']['name'] . '(' . $existingTag['Tag']['id'] . ') successfully removed from ' . $objectType . '(' . $object[$objectType]['id'] . ').';
            return $this->RestResponse->saveSuccessResponse('Tags', 'removeTagFromObject', false, $this->response->type(), $message);
        } else {
            return $this->RestResponse->saveFailResponse('Tags', 'removeTagFromObject', false, 'Failed to remove tag from object.', $this->response->type());
        }
    }

    public function viewGraph($id)
    {
        $tag = $this->Tag->find('first', array(
            'conditions' => array('Tag.id' => $id),
            'recursive' => -1
        ));
        if (empty($tag)) {
            throw new MethodNotAllowedException('Invalid Tag.');
        }
        $this->loadModel('Taxonomy');
        $taxonomy = $this->Taxonomy->getTaxonomyForTag($tag['Tag']['name']);
        if (!empty($taxonomy)) {
            $this->set('taxonomy', $taxonomy);
        }
        $this->set('scope', 'tag');
        $this->set('id', $id);
        $this->render('/Events/view_graph');
    }

    public function search($tag = false, $strictTagNameOnly = false, $searchIfTagExists = true)
    {
        if (isset($this->request->data['Tag'])) {
            $this->request->data = $this->request->data['Tag'];
        }
        if (!empty($this->request->data['tag'])) {
            $tag = $this->request->data['tag'];
        } else if (!empty($this->request->data)) {
            $tag = $this->request->data;
        }
        if (!is_array($tag)) {
            $tag = array($tag);
        }
        $this->loadModel('GalaxyCluster');
        $conditions = array();
        if (!$strictTagNameOnly) {
            $conditionsCluster = [];
            foreach ($tag as $k => $t) {
                $tag[$k] = strtolower($t);
                $conditionsCluster['OR'][] = array('LOWER(GalaxyCluster.value)' => $tag[$k]);
            }
            foreach ($tag as $k => $t) {
                $conditionsCluster['OR'][] = array('AND' => array('GalaxyElement.key' => 'synonyms', 'LOWER(GalaxyElement.value) LIKE' => $t));
            }
            $elements = $this->GalaxyCluster->GalaxyElement->find('all', array(
                'recursive' => -1,
                'conditions' => $conditionsCluster,
                'contain' => array('GalaxyCluster.tag_name')
            ));
            foreach ($elements as $element) {
                $tag[] = strtolower($element['GalaxyCluster']['tag_name']);
            }
            foreach ($tag as $k => $t) {
                $conditions['OR'][] = array('LOWER(Tag.name) LIKE' => $t);
            }
        } else {
            foreach ($tag as $k => $t) {
                $conditions['OR'][] = array('Tag.name' => $t);
            }
        }
        $tags = $this->Tag->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1
        ));
        if (!$searchIfTagExists && empty($tags)) {
            $tags = [];
            foreach ($tag as $i => $tagName) {
                $tags[] = ['Tag' => ['name' => $tagName], 'simulatedTag' => true];
            }
        }
        $this->loadModel('Taxonomy');
        foreach ($tags as $k => $t) {
            $dataFound = false;
            $taxonomy = $this->Taxonomy->getTaxonomyForTag($t['Tag']['name'], false);
            if (!empty($taxonomy) && !empty($taxonomy['TaxonomyPredicate'][0])) {
                $dataFound = true;
                $tags[$k]['Taxonomy'] = $taxonomy['Taxonomy'];
                $tags[$k]['TaxonomyPredicate'] = $taxonomy['TaxonomyPredicate'][0];
            }
            $cluster = $this->GalaxyCluster->getCluster($t['Tag']['name'], $this->Auth->user());
            if (!empty($cluster)) {
                $dataFound = true;
                $tags[$k]['GalaxyCluster'] = $cluster['GalaxyCluster'];
            }
            if (!$searchIfTagExists && !$dataFound && !empty($t['simulatedTag'])) {
                unset($tags[$k]);
            }
        }
        return $this->RestResponse->viewData($tags, $this->response->type());
    }
}
