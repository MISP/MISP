<?php

App::uses('AppController', 'Controller');

class TagsController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'Tag.name' => 'asc'
            ),
            'contain' => array(
                'EventTag' => array(
                    'fields' => array('EventTag.event_id')
                ),
                'AttributeTag' => array(
                    'fields' => array('AttributeTag.event_id', 'AttributeTag.attribute_id')
                ),
                'FavouriteTag',
                'Organisation' => array(
                    'fields' => array('id', 'name')
                )
            )
    );

    public $helpers = array('TextColour');

    public function index($favouritesOnly = false)
    {
        $this->loadModel('Attribute');
        $this->loadModel('Event');
        $this->loadModel('Taxonomy');
        if ($this->_isSiteAdmin()) {
            $this->paginate['contain']['User'] = array('fields' => array('id', 'email'));
        }
        $taxonomies = $this->Taxonomy->listTaxonomies(array('full' => false, 'enabled' => true));
        $taxonomyNamespaces = array();
        if (!empty($taxonomies)) {
            foreach ($taxonomies as $taxonomy) {
                $taxonomyNamespaces[$taxonomy['namespace']] = $taxonomy;
            }
        }
        $taxonomyTags = array();
        $passedArgsArray = array();
        $this->Event->recursive = -1;
        if ($favouritesOnly) {
            $tag_id_list = $this->Tag->FavouriteTag->find('list', array(
                    'conditions' => array('FavouriteTag.user_id' => $this->Auth->user('id')),
                    'fields' => array('FavouriteTag.tag_id')
            ));
            if (empty($tag_id_list)) {
                $tag_id_list = array(-1);
            }
            $this->paginate['conditions']['AND']['Tag.id'] = $tag_id_list;
        }
        if (isset($this->params['named']['searchall'])) {
            $passedArgsArray['all'] = $this->params['named']['searchall'];
        } elseif ($this->request->is('post')) {
            $validNames = array('filter', 'searchall', 'name', 'search');
            foreach ($validNames as $vn) {
                if (!empty($this->request->data[$vn])) {
                    $passedArgsArray['all'] = $this->request->data[$vn];
                    continue;
                }
            }
        }
        if (!empty($passedArgsArray['all'])) {
            $this->paginate['conditions']['AND']['LOWER(Tag.name) LIKE'] = '%' . strtolower($passedArgsArray['all']) . '%';
        }
        if ($this->_isRest()) {
            unset($this->paginate['limit']);
            unset($this->paginate['contain']['EventTag']);
            unset($this->paginate['contain']['AttributeTag']);
            $paginated = $this->Tag->find('all', $this->paginate);
        } else {
            $paginated = $this->paginate();
        }
        $tagList = array();
        $csv = array();
        $sgs = $this->Tag->EventTag->Event->SharingGroup->fetchAllAuthorised($this->Auth->user());
        foreach ($paginated as $k => $tag) {
            $tagList[] = $tag['Tag']['id'];
            $paginated[$k]['Tag']['count'] = $this->Tag->EventTag->countForTag($tag['Tag']['id'], $this->Auth->user(), $sgs);
            if (!$this->_isRest()) {
                $paginated[$k]['event_ids'] = array();
                $paginated[$k]['attribute_ids'] = array();
                foreach ($paginated[$k]['EventTag'] as $et) {
                    $paginated[$k]['event_ids'][] = $et['event_id'];
                }
                unset($paginated[$k]['EventTag']);
                foreach ($paginated[$k]['AttributeTag'] as $at) {
                    $paginated[$k]['attribute_ids'][] = $at['attribute_id'];
                }
                unset($paginated[$k]['AttributeTag']);
            }
            $paginated[$k]['Tag']['attribute_count'] = $this->Tag->AttributeTag->countForTag($tag['Tag']['id'], $this->Auth->user(), $sgs);
            if (!empty($tag['FavouriteTag'])) {
                foreach ($tag['FavouriteTag'] as $ft) {
                    if ($ft['user_id'] == $this->Auth->user('id')) {
                        $paginated[$k]['Tag']['favourite'] = true;
                    }
                }
                if (!isset($paginated[$k]['Tag']['favourite'])) {
                    $paginated[$k]['Tag']['favourite'] = false;
                }
            } else {
                $paginated[$k]['Tag']['favourite'] = false;
            }
            unset($paginated[$k]['FavouriteTag']);
            if (!empty($taxonomyNamespaces)) {
                $taxonomyNamespaceArrayKeys = array_keys($taxonomyNamespaces);
                foreach ($taxonomyNamespaceArrayKeys as $tns) {
                    if (substr(strtoupper($tag['Tag']['name']), 0, strlen($tns)) === strtoupper($tns)) {
                        $paginated[$k]['Tag']['Taxonomy'] = $taxonomyNamespaces[$tns];
                        if (!isset($taxonomyTags[$tns])) {
                            $taxonomyTags[$tns] = $this->Taxonomy->getTaxonomyTags($taxonomyNamespaces[$tns]['id'], true);
                        }
                        $paginated[$k]['Tag']['Taxonomy']['expanded'] = isset($taxonomyTags[$tns][strtoupper($tag['Tag']['name'])]) ? $taxonomyTags[$tns][strtoupper($tag['Tag']['name'])] : $tag['Tag']['name'];
                    }
                }
            }
        }
        if (!$this->_isRest()) {
            $this->loadModel('Sighting');
            $sightings['event'] = $this->Sighting->getSightingsForObjectIds($this->Auth->user(), $tagList);
            $sightings['attribute'] = $this->Sighting->getSightingsForObjectIds($this->Auth->user(), $tagList, 'attribute');
            foreach ($paginated as $k => $tag) {
                $objects = array('event', 'attribute');
                foreach ($objects as $object) {
                    foreach ($tag[$object . '_ids'] as $objectid) {
                        if (isset($sightings[$object][$objectid])) {
                            foreach ($sightings[$object][$objectid] as $date => $sightingCount) {
                                if (!isset($tag['sightings'][$date])) {
                                    $tag['sightings'][$date] = $sightingCount;
                                } else {
                                    $tag['sightings'][$date] += $sightingCount;
                                }
                            }
                        }
                    }
                }
                if (!empty($tag['sightings'])) {
                    $startDate = !empty($tag['sightings']) ? min(array_keys($tag['sightings'])) : date('Y-m-d');
                    $startDate = date('Y-m-d', strtotime("-3 days", strtotime($startDate)));
                    $to = date('Y-m-d', time());
                    for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
                        if (!isset($csv[$k])) {
                            $csv[$k] = 'Date,Close\n';
                        }
                        if (isset($tag['sightings'][$date])) {
                            $csv[$k] .= $date . ',' . $tag['sightings'][$date] . '\n';
                        } else {
                            $csv[$k] .= $date . ',0\n';
                        }
                    }
                }
                unset($paginated[$k]['event_ids']);
            }
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
            $this->set('csv', $csv);
            $this->set('list', $paginated);
            $this->set('favouritesOnly', $favouritesOnly);
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
                $this->set('url', '/tags/delete/' . $id);
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
        $this->loadModel('EventTag');
        if (!$this->EventTag->Event->checkIfAuthorised($this->Auth->user(), $id)) {
            throw new MethodNotAllowedException('Invalid event.');
        }
        $this->loadModel('GalaxyCluster');
        $cluster_names = $this->GalaxyCluster->find('list', array(
            'fields' => array('GalaxyCluster.tag_name'),
            'group' => array('GalaxyCluster.id', 'GalaxyCluster.tag_name')
        ));
        $this->helpers[] = 'TextColour';
        $conditions = array(
                'event_id' => $id,
                'Tag.name !=' => $cluster_names
        );
        $tags = $this->EventTag->find('all', array(
                'conditions' => $conditions,
                'contain' => array('Tag'),
                'fields' => array('Tag.id', 'Tag.colour', 'Tag.name', 'EventTag.local'),
        ));
        foreach ($tags as $k => $tag) {
            $tags[$k]['local'] = $tag['EventTag']['local'];
        }
        $this->set('tags', $tags);
        $event = $this->Tag->EventTag->Event->find('first', array(
                'recursive' => -1,
                'fields' => array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.user_id'),
                'conditions' => array('Event.id' => $id)
        ));
        $this->set('required_taxonomies', $this->EventTag->Event->getRequiredTaxonomies());
        $this->set('event', $event);
        $this->layout = 'ajax';
        $this->render('/Events/ajax/ajaxTags');
    }

    public function showAttributeTag($id)
    {
        $this->helpers[] = 'TextColour';
        $this->loadModel('AttributeTag');

        $this->Tag->AttributeTag->Attribute->id = $id;
        if (!$this->Tag->AttributeTag->Attribute->exists()) {
            throw new NotFoundException(__('Invalid attribute'));
        }
        $this->Tag->AttributeTag->Attribute->read();
        $eventId = $this->Tag->AttributeTag->Attribute->data['Attribute']['event_id'];

        $conditions = array('attribute_id' => $id);
        $attributeTags = $this->AttributeTag->find('all', array(
            'conditions' => $conditions,
            'contain' => array('Tag'),
            'fields' => array('Tag.id', 'Tag.colour', 'Tag.name', 'AttributeTag.local'),
        ));
        foreach ($attributeTags as $k => $at) {
            $attributeTags[$k]['local'] = $at['AttributeTag']['local'];
        }
        $this->loadModel('GalaxyCluster');
        $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id')));
        foreach ($attributeTags as $k => $attributeTag) {
            if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                unset($attributeTags[$k]);
            }
        }
        $event = $this->Tag->AttributeTag->Attribute->Event->find('first', array(
            'recursive' => -1,
            'fields' => array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.user_id'),
            'conditions' => array('Event.id' => $eventId)
        ));
        $this->set('event', $event);
        $this->set('attributeTags', $attributeTags);
        $this->set('attributeId', $id);
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
                'value' => "/tags/selectTag/" . h($id) . "/favourites/" . h($scope) . $localFlag
            );
        }
        if ($scope !== 'tag_collection') {
            $items[] = array(
                'name' => __('Tag Collections'),
                'value' => "/tags/selectTag/" . h($id) . "/collections/" . h($scope) . $localFlag
            );
        }
        $items[] = array(
            'name' => __('Custom Tags'),
            'value' => "/tags/selectTag/" . h($id) . "/0/" . h($scope) . $localFlag
        );
        $items[] = array(
            'name' => __('All Tags'),
            'value' => "/tags/selectTag/" . h($id) . "/all/" . h($scope) . $localFlag
        );

        $this->loadModel('Taxonomy');
        $options = $this->Taxonomy->find('list', array('conditions' => array('enabled' => true), 'fields' => array('namespace'), 'order' => array('Taxonomy.namespace ASC')));
        foreach ($options as $k => $option) {
            $items[] = array(
                'name' => __('Taxonomy Library') . ":" . h($option),
                'value' => "/tags/selectTag/" . h($id) . "/" . h($k) . "/" . h($scope . $localFlag)
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
        $this->set('taxonomy_id', $taxonomy_id);
        if ($taxonomy_id === 'collections') {
            $this->loadModel('TagCollection');
            $tagCollections = $this->TagCollection->fetchTagCollection($this->Auth->user());
            $tags = array();
            $inludedTagListString = array();
            $expanded = array();
            foreach ($tagCollections as &$tagCollection) {
                $tags[$tagCollection['TagCollection']['id']] = $tagCollection['TagCollection'];
                $expanded[$tagCollection['TagCollection']['id']] = empty($tagCollection['TagCollection']['description']) ? $tagCollection['TagCollection']['name'] : $tagCollection['TagCollection']['description'];
                if (!empty($tagCollection['TagCollectionTag'])) {
                    $tagList = array();
                    foreach ($tagCollection['TagCollectionTag'] as $k => $tce) {
                        if (in_array($tce['tag_id'], $banned_tags)) {
                            unset($tagCollection['TagCollectionTag'][$k]);
                        } else {
                            $tagList[] = $tce['Tag']['name'];
                        }
                        $tagCollection['TagCollectionTag'] = array_values($tagCollection['TagCollectionTag']);
                    }
                    $tagList = implode(', ', $tagList);
                    $inludedTagListString[$tagCollection['TagCollection']['id']] = $tagList;
                    $expanded[$tagCollection['TagCollection']['id']] .= sprintf(' (%s)', $tagList);
                }
            }
        } else {
            if ($taxonomy_id === '0') {
                $temp = $this->Taxonomy->getAllTaxonomyTags(true, false, true);
                $tags = array();
                foreach ($temp as $tag) {
                    $tags[$tag['Tag']['id']] = $tag['Tag'];
                }
                unset($temp);
                $expanded = $tags;
            } elseif ($taxonomy_id === 'favourites') {
                $tags = array();
                $conditions = array('FavouriteTag.user_id' => $this->Auth->user('id'));
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
                if (!$this->_isSiteAdmin()) {
                    $conditions = array('Tag.org_id' => array(0, $this->Auth->user('org_id')));
                    $conditions = array('Tag.user_id' => array(0, $this->Auth->user('id')));
                }
                $conditions['Tag.hide_tag'] = 0;
                $allTags = $this->Tag->find('all', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                    'order' => array('name asc'),
                    'fields' => array('Tag.id', 'Tag.name', 'Tag.colour')
                ));
                $tags = array();
                foreach ($allTags as $k => $tag) {
                    $temp = explode(':', $tag['Tag']['name']);
                    if (count($temp) > 1) {
                        if ($temp[0] !== 'misp-galaxy') {
                            $tags[$tag['Tag']['id']] = $tag['Tag'];
                        }
                    } else {
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
            }
            // Unset all tags that this user cannot use for tagging, determined by the org restriction on tags
            if (!$this->_isSiteAdmin()) {
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

    private function __findObjectByUuid($object_uuid, &$type)
    {
        $this->loadModel('Event');
        $object = $this->Event->find('first', array(
            'conditions' => array(
                'Event.uuid' => $object_uuid,
            ),
            'fields' => array('Event.orgc_id', 'Event.id'),
            'recursive' => -1
        ));
        $type = 'Event';
        if (!empty($object)) {
            if (
                !$this->_isSiteAdmin() &&
                !$this->userRole['perm_tagger'] &&
                $object['Event']['orgc_id'] != $this->Auth->user('org_id')
            ) {
                throw new MethodNotAllowedException('Invalid Target.');
            }
        } else {
            $type = 'Attribute';
            $object = $this->Event->Attribute->find('first', array(
                'conditions' => array(
                    'Attribute.uuid' => $object_uuid,
                ),
                'fields' => array('Attribute.id'),
                'recursive' => -1,
                'contain' => array('Event.orgc_id')
            ));
            if (!empty($object)) {
                if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger'] && $object['Event']['orgc_id'] != $this->Auth->user('org_id')) {
                    throw new MethodNotAllowedException('Invalid Target.');
                }
            } else {
                throw new MethodNotAllowedException('Invalid Target.');
            }
        }
        return $object;
    }

    public function attachTagToObject($uuid = false, $tag = false, $local = false)
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
        if (empty($local)) {
            if (!empty($this->request->data['local'])) {
                $local = $this->request->data['local'];
            }
        }
        if (!is_bool($local)) {
            throw new InvalidArgumentException('Invalid local flag');
        }
        $objectType = '';
        $object = $this->__findObjectByUuid($uuid, $objectType);
        $existingTag = $this->Tag->find('first', array('conditions' => $conditions, 'recursive' => -1));
        if (empty($existingTag)) {
            if (!is_numeric($tag)) {
                if (!$this->userRole['perm_tag_editor']) {
                    throw new MethodNotAllowedException('Tag not found and insufficient privileges to create it.');
                }
                $this->Tag->create();
                $this->Tag->save(array('Tag' => array('name' => $tag, 'colour' => $this->Tag->random_color())));
                $existingTag = $this->Tag->find('first', array('recursive' => -1, 'conditions' => array('Tag.id' => $this->Tag->id)));
            } else {
                throw new NotFoundException('Invalid Tag.');
            }
        }
        if (!$this->_isSiteAdmin()) {
            if (!in_array($existingTag['Tag']['org_id'], array(0, $this->Auth->user('org_id')))) {
                throw new MethodNotAllowedException('Invalid Tag.');
            }
            if (!in_array($existingTag['Tag']['user_id'], array(0, $this->Auth->user('id')))) {
                throw new MethodNotAllowedException('Invalid Tag.');
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
            return $this->RestResponse->saveSuccessResponse('Tags', 'attachTagToObject', false, $this->response->type(), $objectType . ' already has the requested tag attached, no changes had to be made.');
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
            if($local) {
                $message = 'Local tag ' . $existingTag['Tag']['name'] . '(' . $existingTag['Tag']['id'] . ') successfully attached to ' . $objectType . '(' . $object[$objectType]['id'] . ').';
            } else {
                if ($objectType === 'Attribute') {
                    $this->$objectType->Event->unpublishEvent($object['Event']['id']);
                } else if ($objectType === 'Event') {
                    $this->Event->unpublishEvent($object['Event']['id']);
                }
                $message = 'Global tag ' . $existingTag['Tag']['name'] . '(' . $existingTag['Tag']['id'] . ') successfully attached to ' . $objectType . '(' . $object[$objectType]['id'] . ').';
            }
            return $this->RestResponse->saveSuccessResponse('Tags', 'attachTagToObject', false, $this->response->type(), $message);
        } else {
            return $this->RestResponse->saveFailResponse('Tags', 'attachTagToObject', false, 'Failed to attach tag to object.', $this->response->type());
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
        $object = $this->__findObjectByUuid($uuid, $objectType);
        if (empty($object)) {
            throw new MethodNotAllowedException('Invalid Target.');
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

    public function search($tag = false)
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
        $conditions = array();
        foreach ($tag as $k => $t) {
            $tag[$k] = strtolower($t);
            $conditions['OR'][] = array('LOWER(GalaxyCluster.value)' => $tag[$k]);
        }
        foreach ($tag as $k => $t) {
            $conditions['OR'][] = array('AND' => array('GalaxyElement.key' => 'synonyms', 'LOWER(GalaxyElement.value) LIKE' => $t));
        }
        $this->loadModel('GalaxyCluster');
        $elements = $this->GalaxyCluster->GalaxyElement->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => array('GalaxyCluster.tag_name')
        ));
        foreach ($elements as $element) {
            $tag[] = strtolower($element['GalaxyCluster']['tag_name']);
        }
        $conditions = array();
        foreach ($tag as $k => $t) {
            $conditions['OR'][] = array('LOWER(Tag.name) LIKE' => $t);
        }
        $tags = $this->Tag->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1
        ));
        $this->loadModel('Taxonomy');
        foreach ($tags as $k => $t) {
            $taxonomy = $this->Taxonomy->getTaxonomyForTag($t['Tag']['name'], true);
            if (!empty($taxonomy)) {
                $tags[$k]['Taxonomy'] = $taxonomy['Taxonomy'];
            }
            $cluster = $this->GalaxyCluster->getCluster($t['Tag']['name']);
            if (!empty($cluster)) {
                $tags[$k]['GalaxyCluster'] = $cluster['GalaxyCluster'];
            }
        }
        return $this->RestResponse->viewData($tags, $this->response->type());
    }
}
