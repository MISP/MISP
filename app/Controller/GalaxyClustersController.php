<?php
App::uses('AppController', 'Controller');

class GalaxyClustersController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'recursive' => -1,
            'order' => array(
                'GalaxyCluster.value' => 'ASC'
            ),
            'contain' => array(
                'Tag' => array(
                    'fields' => array('Tag.id'),
                    /*
                    'EventTag' => array(
                        'fields' => array('EventTag.event_id')
                    ),
                    'AttributeTag' => array(
                        'fields' => array('AttributeTag.event_id', 'AttributeTag.attribute_id')
                    )
                    */
                ),
                'GalaxyElement' => array(
                    'conditions' => array('GalaxyElement.key' => 'synonyms'),
                    'fields' => array('value')
                ),
            )
    );

    public function index($id)
    {
        $this->paginate['conditions'] = array('GalaxyCluster.galaxy_id' => $id);
        if (isset($this->params['named']['searchall']) && strlen($this->params['named']['searchall']) > 0) {
            $synonym_hits = $this->GalaxyCluster->GalaxyElement->find(
                'list',
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'LOWER(GalaxyElement.value) LIKE' => '%' . strtolower($this->params['named']['searchall']) . '%',
                        'GalaxyElement.key' => 'synonyms' ),
                        'fields' => array(
                            'GalaxyElement.galaxy_cluster_id')
                        )
            );
            $this->paginate['conditions'] =
                array("AND" => array(
                    'OR' => array(
                        "LOWER(GalaxyCluster.value) LIKE" => '%'. strtolower($this->params['named']['searchall']) .'%',
                        "LOWER(GalaxyCluster.description) LIKE" => '%'. strtolower($this->params['named']['searchall']) .'%',
                        "GalaxyCluster.id" => array_values($synonym_hits)
                    ),
                    "GalaxyCluster.galaxy_id" => $id
                    ));
            $this->set('passedArgsArray', array('all'=>$this->params['named']['searchall']));
        }
        $clusters = $this->paginate();
        $sgs = $this->GalaxyCluster->Tag->EventTag->Event->SharingGroup->fetchAllAuthorised($this->Auth->user());
        foreach ($clusters as $k => $cluster) {
            if (!empty($cluster['Tag']['id'])) {
                $clusters[$k]['GalaxyCluster']['event_count'] = $this->GalaxyCluster->Tag->EventTag->countForTag($cluster['Tag']['id'], $this->Auth->user(), $sgs);
            }
        }
        $tagIds = array();
        $sightings = array();
        if (!empty($clusters)) {
            $galaxyType = $clusters[0]['GalaxyCluster']['type'];
            foreach ($clusters as $k => $v) {
                $clusters[$k]['event_ids'] = array();
                if (!empty($v['Tag'])) {
                    $tagIds[] = $v['Tag']['id'];
                    $clusters[$k]['GalaxyCluster']['tag_id'] = $v['Tag']['id'];
                }
                $clusters[$k]['GalaxyCluster']['synonyms'] = array();
                foreach ($v['GalaxyElement'] as $element) {
                    $clusters[$k]['GalaxyCluster']['synonyms'][] = $element['value'];
                }
            }
        }
        $this->loadModel('Sighting');
        $sightings['tags'] = array();
        foreach ($clusters as $k => $cluster) {
            if (!empty($cluster['GalaxyCluster']['tag_id'])) {
                $temp = $this->Sighting->getSightingsForTag($this->Auth->user(), $cluster['GalaxyCluster']['tag_id']);
                $clusters[$k]['sightings'] = $temp;
            }
        }
        $csv = array();
        foreach ($clusters as $k => $cluster) {
            $startDate = !empty($cluster['sightings']) ? min(array_keys($cluster['sightings'])) : date('Y-m-d');
            $startDate = date('Y-m-d', strtotime("-3 days", strtotime($startDate)));
            $to = date('Y-m-d', time());
            for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
                if (!isset($csv[$k])) {
                    $csv[$k] = 'Date,Close\n';
                }
                if (isset($cluster['sightings'][$date])) {
                    $csv[$k] .= $date . ',' . $cluster['sightings'][$date] . '\n';
                } else {
                    $csv[$k] .= $date . ',0\n';
                }
            }
        }
        $this->set('csv', $csv);
        $this->set('list', $clusters);
        $this->set('galaxy_id', $id);
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }

    public function view($id)
    {
        $conditions = array('GalaxyCluster.id' => $id);
        if (Validation::uuid($id)) {
            $conditions = array('GalaxyCluster.uuid' => $id);
        }
        $contain = array('Galaxy');
        if ($this->_isRest()) {
            $contain[] = 'GalaxyElement';
        }
        $cluster = $this->GalaxyCluster->find('first', array(
            'recursive' => -1,
            'contain' => $contain,
            'conditions' => $conditions
        ));
        if (!empty($cluster)) {
            $galaxyType = $cluster['GalaxyCluster']['type'];
            $this->loadModel('Tag');
            $tag = $this->Tag->find('first', array(
                    'conditions' => array(
                            'name' => $cluster['GalaxyCluster']['tag_name']
                    ),
                    'fields' => array('id'),
                    'recursive' => -1,
                    'contain' => array('EventTag.tag_id')
            ));
            if (!empty($tag)) {
                $cluster['GalaxyCluster']['tag_count'] = count($tag['EventTag']);
                $cluster['GalaxyCluster']['tag_id'] = $tag['Tag']['id'];
            }
        } else {
            throw new NotFoundException('Cluster not found.');
        }
        if ($this->_isRest()) {
            $cluster['GalaxyCluster']['Galaxy'] = $cluster['Galaxy'];
            $cluster['GalaxyCluster']['GalaxyElement'] = $cluster['GalaxyElement'];
            return $this->RestResponse->viewData(array('GalaxyCluster' => $cluster['GalaxyCluster']), $this->response->type());
        } else {
            $this->set('id', $id);
            $this->set('galaxy_id', $cluster['Galaxy']['id']);
            $this->set('cluster', $cluster);
        }
    }

    public function attachToEvent($event_id, $tag_name)
    {
        $this->loadModel('Event');
        $this->Event->id = $event_id;
        $this->Event->recursive = -1;
        $event = $this->Event->read(array(), $event_id);
        if (empty($event)) {
            throw new MethodNotAllowedException('Invalid Event.');
        }
        if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
            if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
                throw new MethodNotAllowedException('Invalid Event.');
            }
        }
        $tag = $this->Event->EventTag->Tag->find('first', array('conditions' => array('Tag.name' => $tag_name), 'recursive' => -1));
        if (empty($tag)) {
            $this->Event->EventTag->Tag->create();
            $this->Event->EventTag->Tag->save(array('name' => $tag_name, 'colour' => '#0088cc', 'exportable' => 1));
            $tag_id = $this->Event->EventTag->Tag->id;
        } else {
            $tag_id = $tag['Tag']['id'];
        }
        $existingEventTag = $this->Event->EventTag->find('first', array('conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id), 'recursive' => -1));
        if (empty($existingEventTag)) {
            $cluster = $this->GalaxyCluster->find('first', array(
                'recursive' => -1,
                'conditions' => array('GalaxyCluster.tag_name' => $existingEventTag['Tag']['name'])
            ));
            $this->Event->EventTag->create();
            $this->Event->EventTag->save(array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $event_id));
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                'org' => $this->Auth->user('Organisation')['name'],
                'model' => 'Event',
                'model_id' => $event_id,
                'email' => $this->Auth->user('email'),
                'action' => 'galaxy',
                'title' => 'Attached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to event (' . $event_id . ')',
                'change' => ''
            ));
            $event['Event']['published'] = 0;
            $date = new DateTime();
            $event['Event']['timestamp'] = $date->getTimestamp();
            $this->Event->save($event);
            $this->Flash->success('Galaxy attached.');
        } else {
            $this->Flash->error('Galaxy already attached.');
        }
        $this->redirect($this->referer());
    }

    public function detach($target_id, $target_type, $tag_id)
    {
        $this->loadModel('Event');
        if ($target_type == 'attribute') {
            $attribute = $this->Event->Attribute->find('first', array(
                'recursive' => -1,
                'fields' => array('id', 'event_id'),
                'conditions' => array('Attribute.id' => $target_id)
            ));
            if (empty($attribute)) {
                throw new MethodNotAllowedException('Invalid Attribute.');
            }
            $event_id = $attribute['Attribute']['event_id'];
        } elseif ($target_type == 'event') {
            $event_id = $target_id;
        } elseif ($target_type === 'tag_collection') {
            // pass
        } else {
            throw new MethodNotAllowedException('Invalid options');
        }

        if ($target_type === 'tag_collection') {
            $tag_collection = $this->GalaxyCluster->Tag->TagCollectionTag->TagCollection->fetchTagCollection($this->Auth->user(), array(
                'conditions' => array('TagCollection.id' => $target_id),
                'contain' => array('Organisation', 'TagCollectionTag' => array('Tag'))
            ));
            if (empty($tag_collection)) {
                throw new MethodNotAllowedException('Invalid Tag Collection');
            }
            $tag_collection = $tag_collection[0];
            if (!$this->_isSiteAdmin()) {
                if (!$this->userRole['perm_tag_editor'] || $this->Auth->user('org_id') !== $tag_collection['TagCollection']['org_id']) {
                    throw new MethodNotAllowedException('Invalid Tag Collection');
                }
            }
        } else {
            $this->Event->id = $event_id;
            $this->Event->recursive = -1;
            $event = $this->Event->read(array(), $event_id);
            if (empty($event)) {
                throw new MethodNotAllowedException('Invalid Event.');
            }
            if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
                if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
                    throw new MethodNotAllowedException('Invalid Event.');
                }
            }
        }

        if ($target_type == 'attribute') {
            $existingTargetTag = $this->Event->Attribute->AttributeTag->find('first', array(
                'conditions' => array('AttributeTag.tag_id' => $tag_id, 'AttributeTag.attribute_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type == 'event') {
            $existingTargetTag = $this->Event->EventTag->find('first', array(
                'conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type == 'tag_collection') {
            $existingTargetTag = $this->GalaxyCluster->Tag->TagCollectionTag->find('first', array(
                'conditions' => array('TagCollectionTag.tag_id' => $tag_id, 'TagCollectionTag.tag_collection_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        }

        if (empty($existingTargetTag)) {
            $this->Flash->error('Galaxy not attached.');
        } else {
            $cluster = $this->GalaxyCluster->find('first', array(
                'recursive' => -1,
                'conditions' => array('GalaxyCluster.tag_name' => $existingTargetTag['Tag']['name'])
            ));
            if ($target_type == 'event') {
                $result = $this->Event->EventTag->delete($existingTargetTag['EventTag']['id']);
            } elseif ($target_type == 'attribute') {
                $result = $this->Event->Attribute->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
            } elseif ($target_type == 'tag_collection') {
                $result = $this->GalaxyCluster->Tag->TagCollectionTag->delete($existingTargetTag['TagCollectionTag']['id']);
            }
            if ($result) {
                $event['Event']['published'] = 0;
                $date = new DateTime();
                $event['Event']['timestamp'] = $date->getTimestamp();
                $this->Event->save($event);
                $this->Flash->success('Galaxy successfully detached.');
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->save(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => ucfirst($target_type),
                    'model_id' => $target_id,
                    'email' => $this->Auth->user('email'),
                    'action' => 'galaxy',
                    'title' => 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') from ' . $target_type . ' (' . $target_id . ')',
                    'change' => ''
                ));
            } else {
                $this->Flash->error('Could not detach galaxy from event.');
            }
        }
        $this->redirect($this->referer());
    }

    public function delete($id)
    {
        {
            if ($this->request->is('post')) {
                $result = false;
                $galaxy_cluster = $this->GalaxyCluster->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('GalaxyCluster.id' => $id)
                ));
                if (!empty($galaxy_cluster)) {
                    $result = $this->GalaxyCluster->delete($id, true);
                    $galaxy_id = $galaxy_cluster['GalaxyCluster']['galaxy_id'];
                }
                if ($result) {
                    $message = 'Galaxy cluster successfuly deleted.';
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'delete', $id, $this->response->type());
                    } else {
                        $this->Flash->success($message);
                        $this->redirect(array('controller' => 'galaxies', 'action' => 'view', $galaxy_id));
                    }
                } else {
                    $message = 'Galaxy cluster could not be deleted.';
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('GalaxyCluster', 'delete', $id, $message, $this->response->type());
                    } else {
                        $this->Flash->error($message);
                        $this->redirect(array('controller' => 'taxonomies', 'action' => 'index'));
                    }
                }
            } else {
                if ($this->request->is('ajax')) {
                    $this->set('id', $id);
                    $this->render('ajax/galaxy_cluster_delete_confirmation');
                } else {
                    throw new MethodNotAllowedException('This function can only be reached via AJAX.');
                }
            }
        }
    }

    public function viewGalaxyMatrix($id) {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be reached via AJAX.');
        }

        $cluster = $this->GalaxyCluster->find('first', array(
            'conditions' => array('id' => $id)
        ));
        if (empty($cluster)) {
            throw new Exception("Invalid Galaxy Cluster.");
        }
        $this->loadModel('Event');
        $mitreAttackGalaxyId = $this->GalaxyCluster->Galaxy->getMitreAttackGalaxyId();
        $attackPatternTagNames = $this->GalaxyCluster->find('list', array(
            'conditions' => array('galaxy_id' => $mitreAttackGalaxyId),
            'fields' => array('tag_name')
        ));

        $cluster = $cluster['GalaxyCluster'];
        $tag_name = $cluster['tag_name'];

        // fetch all attribute ids having the requested cluster
        $attributeIds = $this->Event->Attribute->AttributeTag->find('list', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'Tag.name' => $tag_name
            ),
            'fields' => array('attribute_id'),
            'recursive' => -1
        ));
        // fetch all related tags belonging to attack pattern
        $attributeTags = $this->Event->Attribute->AttributeTag->find('all', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'attribute_id' => $attributeIds,
                'Tag.name' => $attackPatternTagNames
            ),
            'fields' => array('Tag.name, COUNT(DISTINCT event_id) as tag_count'),
            'recursive' => -1,
            'group' => array('Tag.name')
        ));

        // fetch all event ids having the requested cluster
        $eventIds = $this->Event->EventTag->find('list', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'Tag.name' => $tag_name
            ),
            'fields' => array('event_id'),
            'recursive' => -1
        ));
        // fetch all related tags belonging to attack pattern
        $eventTags = $this->Event->EventTag->find('all', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'event_id' => $eventIds,
                'Tag.name' => $attackPatternTagNames
            ),
            'fields' => array('Tag.name, COUNT(DISTINCT event_id) as tag_count'),
            'recursive' => -1,
            'group' => array('Tag.name')
        ));

        $scores = array();
        foreach ($attributeTags as $tag) {
            $tagName = $tag['Tag']['name'];
            $scores[$tagName] = intval($tag[0]['tag_count']);
        }
        foreach ($eventTags as $tag) {
            $tagName = $tag['Tag']['name'];
            if (isset($scores[$tagName])) {
                $scores[$tagName] = $scores[$tagName] + intval($tag[0]['tag_count']);
            } else {
                $scores[$tagName] = intval($tag[0]['tag_count']);
            }
        }

        $maxScore = count($scores) > 0 ? max(array_values($scores)) : 0;
        $matrixData = $this->GalaxyCluster->Galaxy->getMatrix($mitreAttackGalaxyId);
        $tabs = $matrixData['tabs'];
        $matrixTags = $matrixData['matrixTags'];
        $killChainOrders = $matrixData['killChain'];
        $instanceUUID = $matrixData['instance-uuid'];

        App::uses('ColourGradientTool', 'Tools');
        $gradientTool = new ColourGradientTool();
        $colours = $gradientTool->createGradientFromValues($scores);
        $this->set('target_type', 'attribute');
        $this->set('columnOrders', $killChainOrders);
        $this->set('tabs', $tabs);
        $this->set('scores', $scores);
        $this->set('maxScore', $maxScore);
        if (!empty($colours)) {
            $this->set('colours', $colours['mapping']);
            $this->set('interpolation', $colours['interpolation']);
        }
        $this->set('pickingMode', false);
        $this->set('defaultTabName', 'mitre-attack');
        $this->set('removeTrailling', 2);

        $this->render('cluster_matrix');
    }
}
