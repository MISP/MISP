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
        $filters = $this->IndexFilter->harvestParameters(array('context', 'searchall'));
        $aclConditions = $this->GalaxyCluster->buildConditions($this->Auth->user());
        $contextConditions = array();
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        } else {
            $contextConditions = array();
            if ($filters['context'] == 'default') {
                $contextConditions = array(
                    'GalaxyCluster.default' => true
                );
            } elseif ($filters['context'] == 'custom') {
                $contextConditions = array(
                    'GalaxyCluster.default' => false
                );
            } elseif ($filters['context'] == 'org') {
                $contextConditions = array(
                    'GalaxyCluster.org_id' => $this->Auth->user('org_id')
                );
            }
        }
        $this->set('passedArgsArray', array('context' => $filters['context'], 'searchall' => isset($filters['searchall']) ? $filters['searchall'] : ''));
        $this->set('context', $filters['context']);
        $searchConditions = array();
        if (empty($filters['searchall'])) {
            $filters['searchall'] = '';
        }
        if (strlen($filters['searchall']) > 0) {
            $searchall = '%' . strtolower($filters['searchall']) . '%';
            $synonym_hits = $this->GalaxyCluster->GalaxyElement->find(
                'list',
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'LOWER(GalaxyElement.value) LIKE' => $searchall,
                        'GalaxyElement.key' => 'synonyms' ),
                        'fields' => array(
                            'GalaxyElement.galaxy_cluster_id')
                        )
            );
            $searchConditions = array(
                'OR' => array(
                    'LOWER(GalaxyCluster.value) LIKE' => $searchall,
                    'LOWER(GalaxyCluster.description) LIKE' => $searchall,
                    'GalaxyCluster.uuid' => $filters['searchall'],
                    'GalaxyCluster.id' => array_values($synonym_hits),
                ),
            );
        }
        $searchConditions['GalaxyCluster.galaxy_id'] = $id;

        if ($this->_isRest()) {
            $clusters = $this->Galaxy->find('all', 
                array(
                    // 'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($contextConditions, $searchConditions, $aclConditions)
                    ),
                )
            );
            return $this->RestResponse->viewData($galaxies, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $contextConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $this->paginate['contain'] = array_merge($this->paginate['contain'], array('Org', 'Orgc', 'SharingGroup', 'GalaxyClusterRelation', 'TargettingClusterRelation'));
            $clusters = $this->paginate();
            foreach ($clusters as $k => $cluster) {
                $clusters[$k] = $this->GalaxyCluster->attachExtendByInfo($this->Auth->user(), $clusters[$k]);
                $clusters[$k] = $this->GalaxyCluster->attachExtendFromInfo($this->Auth->user(), $clusters[$k]);
            }
            $sgs = $this->GalaxyCluster->Tag->EventTag->Event->SharingGroup->fetchAllAuthorised($this->Auth->user());
            foreach ($clusters as $k => $cluster) {
                if (!empty($cluster['Tag']['id'])) {
                    $clusters[$k]['GalaxyCluster']['event_count'] = $this->GalaxyCluster->Tag->EventTag->countForTag($cluster['Tag']['id'], $this->Auth->user(), $sgs);
                } else {
                    $clusters[$k]['GalaxyCluster']['event_count'] = 0;
                }
                $clusters[$k]['GalaxyCluster']['relation_counts'] = array(
                    'out' => count($clusters[$k]['GalaxyClusterRelation']),
                    'in' => count($clusters[$k]['TargettingClusterRelation']),
                );
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
            $this->loadModel('Attribute');
            $distributionLevels = $this->Attribute->distributionLevels;
            unset($distributionLevels[5]);
            $this->set('distributionLevels', $distributionLevels);
            $this->set('csv', $csv);
            $this->set('list', $clusters);
            $this->set('galaxy_id', $id);
        }
        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }

    public function view($id)
    {
        $conditions = array();
        if (Validation::uuid($id)) {
            $conditions['GalaxyCluster.uuid'] = $id;
        } else {
            $conditions['GalaxyCluster.id'] = $id;
        }
        $contain = array('Galaxy', 'Orgc', 'Org');
        if ($this->_isRest()) {
            $contain[] = 'GalaxyElement';
        }
        $options = array(
            'conditions' => $conditions,
            // 'contain' => $contain
        );
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $options, $full=true);
        if (!empty($cluster)) {
            $cluster = $cluster[0];
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
            return $this->RestResponse->viewData($cluster, $this->response->type());
            // return $this->RestResponse->viewData(array('GalaxyCluster' => $cluster['GalaxyCluster']), $this->response->type());
        } else {
            $cluster = $this->GalaxyCluster->attachExtendByInfo($this->Auth->user(), $cluster);
            $cluster = $this->GalaxyCluster->attachExtendFromInfo($this->Auth->user(), $cluster);
            $this->set('id', $id);
            $this->set('galaxy_id', $cluster['GalaxyCluster']['galaxy_id']);
            $this->set('cluster', $cluster);
            $this->set('defaultCluster', $cluster['GalaxyCluster']['default']);
            if (!empty($cluster['GalaxyCluster']['extended_from'])) {
                $newVersionAvailable = $cluster['GalaxyCluster']['extended_from']['GalaxyCluster']['version'] > $cluster['GalaxyCluster']['extends_version'];
            } else {
                $newVersionAvailable = false;
            }
            $this->set('newVersionAvailable', $newVersionAvailable);
            $this->loadModel('Attribute');
            $distributionLevels = $this->Attribute->distributionLevels;
            $this->set('distributionLevels', $distributionLevels);
        }
    }

    public function add($galaxyId)
    {
        $this->loadModel('Attribute');
        $distributionLevels = $this->Attribute->distributionLevels;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->loadModel('SharingGroup');
        $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);

        if (isset($this->params['named']['forkUuid'])) {
            $forkUuid = $this->params['named']['forkUuid'];
            $origCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
                'conditions' => array('GalaxyCluster.uuid' => $forkUuid),
            ), true);
            if (!empty($origCluster)) {
                $origCluster = $origCluster[0];
                $origClusterMeta = $origCluster['GalaxyCluster'];
                $forkVersion = $origCluster['GalaxyCluster']['version'];
                $this->set('forkUuid', $forkUuid);
                $this->set('forkVersion', $forkVersion);
                if (empty($this->request->data)) {
                    $this->request->data = $origCluster;
                    unset($this->request->data['GalaxyCluster']['id']);
                    unset($this->request->data['GalaxyCluster']['uuid']);
                    foreach ($origCluster['GalaxyElement'] as $k => $element) {
                        unset($origCluster['GalaxyElement'][$k]['id']);
                        unset($origCluster['GalaxyElement'][$k]['galaxy_cluster_id']);
                    }
                    $this->request->data['GalaxyCluster']['elements'] = json_encode($origCluster['GalaxyElement']);
                    $this->request->data['GalaxyCluster']['elementsDict'] = $origCluster['GalaxyElement'];
                    $this->request->data['GalaxyCluster']['authors'] = json_encode($origCluster['GalaxyCluster']['authors']);
                }
                $this->set('origCluster', $origCluster);
                $this->set('origClusterMeta', $origClusterMeta);
            } else {
                throw new NotFoundException('Forked cluster not found.');
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $cluster = $this->request->data;
            $errors = array();
            if (empty($cluster['GalaxyCluster']['elements'])) {
                $galaxy['Galaxy']['values'] = array();
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['elements'], true);
                if ($decoded === null) {
                    $decoded = array();
                }
                $galaxy['Galaxy']['elements'] = $decoded;
            }
            $extendId = $this->Toolbox->findIdByUuid($this->GalaxyCluster, $cluster['GalaxyCluster']['forkUuid']);
            $extendedCluster = $this->GalaxyCluster->fetchGalaxyClusters(
                $this->Auth->user(),
                array('conditions' => array('GalaxyCluster.id' => $extendId))
            );
            if (!empty($extendedCluster)) {
                $cluster['GalaxyCluster']['extends_uuid'] = $extendedCluster[0]['GalaxyCluster']['uuid'];
            } else {
                $cluster['GalaxyCluster']['extends_uuid'] = '';
            }
            if ($cluster['GalaxyCluster']['distribution'] != 4) {
                $cluster['GalaxyCluster']['sharing_group_id'] = null;
            }
            $saveSuccess = $this->GalaxyCluster->saveCluster($this->Auth->user(), $cluster);
            if (!$saveSuccess) {
                foreach($this->GalaxyCluster->validationErrors as $validationError) {
                    $errors[] = $validationError;
                }
            }
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', implode(' ', $errors));
                $this->Flash->error($flashErrorMessage);
            } else {
                $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $this->GalaxyCluster->id));
            }
        }
        $this->set('galaxy_id', $galaxyId);
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'add');
    }

    public function edit($id)
    {
        if (Validation::uuid($id)) {
            $temp = $this->GalaxyCluster->find('first', array(
                'recursive' => -1,
                'fields' => array('GalaxyCluster.id', 'GalaxyCluster.uuid'),
                'conditions' => array('GalaxyCluster.uuid' => $id)
            ));
            if ($temp === null) {
                throw new NotFoundException(__('Invalid galaxy cluster'));
            }
            $id = $temp['GalaxyCluster']['id'];
        } elseif (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid galaxy cluster'));
        }
        $conditions = array('conditions' => array('GalaxyCluster.id' => $id));
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $conditions, true);
        if (empty($cluster)) {
            throw new NotFoundException(__('Invalid galaxy cluster'));
        }
        $cluster = $cluster[0];
        if ($cluster['GalaxyCluster']['default']) {
            throw new MethodNotAllowedException('Default galaxy cluster cannot be edited');
        }
        $this->GalaxyCluster->data = array('GalaxyCluster' => $cluster['GalaxyCluster'], 'GalaxyElement' => $cluster['GalaxyElement']);

        $this->loadModel('Attribute');
        $distributionLevels = $this->Attribute->distributionLevels;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->loadModel('SharingGroup');
        $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);

        $origCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
            'conditions' => array('uuid' => $cluster['GalaxyCluster']['extends_uuid']),
        ), false);

        if (!empty($origCluster)) {
            $origCluster = $origCluster[0];
            $this->set('forkUuid', $cluster['GalaxyCluster']['extends_uuid']);
            $origClusterMeta = $origCluster['GalaxyCluster'];
            $this->set('origCluster', $origCluster);
            $this->set('origClusterMeta', $origClusterMeta);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $cluster = $this->request->data;
            $errors = array();
            if (!isset($cluster['GalaxyCluster']['uuid'])) { 
                $cluster['GalaxyCluster']['uuid'] = $this->GalaxyCluster->data['GalaxyCluster']['uuid']; // freeze the uuid
            }
            if (!isset($cluster['GalaxyCluster']['id'])) { 
                $cluster['GalaxyCluster']['id'] = $id;
            }
            if (empty($cluster['GalaxyCluster']['elements'])) {
                $cluster['GalaxyCluster']['elements'] = array();
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['elements'], true);
                if (is_null($decoded)) {
                    $this->GalaxyCluster->validationErrors['values'][] = __('Invalid JSON');
                    $errors[] = sprintf(__('Invalid JSON'));
                }
                $cluster['GalaxyCluster']['elements'] = $decoded;
            }
            if (empty($cluster['GalaxyCluster']['authors'])) {
                $cluster['GalaxyCluster']['authors'] = [];
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['authors'], true);
                if (is_null($decoded)) { // authors might be comma separated
                    $decoded = array_map('trim', explode(',', $cluster['GalaxyCluster']['authors']));
                }
                $cluster['GalaxyCluster']['authors'] = $decoded;
            }
            $cluster['GalaxyCluster']['authors'] = json_encode($cluster['GalaxyCluster']['authors']);
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', $errors);
                $this->Flash->error($flashErrorMessage);
            } else {
                $errors = $this->GalaxyCluster->editCluster($this->Auth->user(), $cluster);
                if (!empty($errors)) {
                    $flashErrorMessage = implode(', ', $errors);
                    $this->Flash->error($flashErrorMessage);
                } else {
                    $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $id));
                }
            }
        } else {
            $this->GalaxyCluster->data['GalaxyCluster']['elements'] = json_encode($this->GalaxyCluster->data['GalaxyElement']);
            $this->GalaxyCluster->data['GalaxyCluster']['elementsDict'] = $this->GalaxyCluster->data['GalaxyElement'];
            $this->GalaxyCluster->data['GalaxyCluster']['authors'] = json_encode($this->GalaxyCluster->data['GalaxyCluster']['authors']);
            $this->request->data = $this->GalaxyCluster->data;
        }
        $fieldDesc = array(
            'authors' => __('Valid JSON array or comma separated'),
            'elements' => __('Valid JSON array composed from Object of the form {key: keyname, value: actualValue}'),
            'distribution' => Hash::extract($this->Attribute->distributionDescriptions, '{n}.formdesc'),
        );
        $this->set('fieldDesc', $fieldDesc);
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('galaxy_id', $cluster['GalaxyCluster']['galaxy_id']);
        $this->set('clusterId', $id);
        $this->set('defaultCluster', $cluster['GalaxyCluster']['default']);
        $this->set('action', 'edit');
        $this->render('add');
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

    // TODO: Add support for custom cluster deletion
    public function delete($id)
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

        // fetch all event ids having the requested cluster
        $eventIds = $this->Event->EventTag->find('list', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'Tag.name' => $tag_name
            ),
            'fields' => array('event_id'),
            'recursive' => -1
        ));

        // fetch all attribute ids having the requested cluster
        $attributes = $this->Event->Attribute->AttributeTag->find('all', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'Tag.name' => $tag_name
            ),
            'fields' => array('attribute_id', 'event_id'),
            'recursive' => -1
        ));
        $attributeIds = array();
        $additional_event_ids = array();
        foreach ($attributes as $attribute) {
            $attributeIds[] = $attribute['AttributeTag']['attribute_id'];
            $additional_event_ids[$attribute['AttributeTag']['event_id']] = $attribute['AttributeTag']['event_id'];
        }
        $additional_event_ids = array_keys($additional_event_ids);
        $eventIds = array_merge($eventIds, $additional_event_ids);
        unset($attributes);
        unset($additional_event_ids);

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

        // fetch all related tags belonging to attack pattern or belonging to an event having this cluster
        $attributeTags = $this->Event->Attribute->AttributeTag->find('all', array(
            'contain' => array('Tag'),
            'conditions' => array(
                'OR' => array(
                    'event_id' => $eventIds,
                    'attribute_id' => $attributeIds
                ),
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
        $matrixData = $this->GalaxyCluster->Galaxy->getMatrix($mitreAttackGalaxyId, $scores);
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

    public function updateCluster($clusterId)
    {
        if (Validation::uuid($clusterId)) {
            $temp = $this->GalaxyCluster->find('first', array(
                'recursive' => -1,
                'fields' => array('GalaxyCluster.id', 'GalaxyCluster.uuid'),
                'conditions' => array('GalaxyCluster.uuid' => $clusterId)
            ));
            if ($temp === null) {
                throw new NotFoundException('Invalid galaxy cluster');
            }
            $clusterId = $temp['GalaxyCluster']['id'];
        } elseif (!is_numeric($clusterId)) {
            throw new NotFoundException(__('Invalid galaxy cluster'));
        }
        $conditions = array('conditions' => array('GalaxyCluster.id' => $clusterId));
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $conditions, true);
        if (empty($cluster)) {
            throw new NotFoundException('Invalid galaxy cluster');
        }
        $cluster = $cluster[0];
        if ($cluster['GalaxyCluster']['default']) {
            throw new MethodNotAllowedException(__('Default galaxy cluster cannot be updated'));
        }
        if (empty($cluster['GalaxyCluster']['extends_uuid'])) {
            throw new NotFoundException(__('Galaxy cluster is not a fork'));
        }
        $conditions = array('conditions' => array('GalaxyCluster.uuid' => $cluster['GalaxyCluster']['extends_uuid']));
        $parentCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $conditions, true);
        if (empty($parentCluster)) {
            throw new NotFoundException('Invalid parent galaxy cluster');
        }
        $parentCluster = $parentCluster[0];
        $forkVersion = $cluster['GalaxyCluster']['extends_version'];
        $parentVersion = $parentCluster['GalaxyCluster']['version'];
        if ($this->request->is('post') || $this->request->is('put')) {
            $elements = array();
            foreach ($this->request->data['GalaxyCluster'] as $k => $jElement) {
                $element = json_decode($jElement, true);
                $elements[] = array(
                    'key' => $element['key'],
                    'value' => $element['value'],
                );
            }
            $cluster['GalaxyCluster']['elements'] = $elements;
            $cluster['GalaxyCluster']['extends_version'] = $parentVersion;
            $errors = $this->GalaxyCluster->editCluster($this->Auth->user(), $cluster, $fromPull=false, $fieldList=array('extends_version'));
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', $errors);
                $this->Flash->error($flashErrorMessage);
            } else {
                $this->Flash->success(__('Cluster updated to the newer version'));
                $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $clusterId));
            }
        }
        $missingElements = array();
        forEach($parentCluster['GalaxyElement'] as $k => $parentElement) {
            $found = false;
            forEach($cluster['GalaxyElement'] as $k => $clusterElement) {
                if ($parentElement['key'] == $clusterElement['key'] &&
                    $parentElement['value'] == $clusterElement['value']) {
                        $found = true;
                    break; // element exists in parent
                }
            }
            if (!$found) {
                $missingElements[] = $parentElement;
            }
        }
        $this->set('missingElements', $missingElements);
        $this->set('parentElements', $parentCluster['GalaxyElement']);
        $this->set('clusterElements', $cluster['GalaxyElement']);
        $this->set('forkVersion', $forkVersion);
        $this->set('parentVersion', $parentVersion);
        $this->set('newVersionAvailable', $parentVersion > $forkVersion);
        $this->set('id', $clusterId);
        $this->set('galaxy_id', $cluster['GalaxyCluster']['galaxy_id']);
        $this->set('defaultCluster', $cluster['GalaxyCluster']['default']);
        $this->set('cluster', $cluster);
    }

    public function viewRelations($id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be reached via AJAX.');
        }
        $conditions = array('conditions' => array('GalaxyCluster.id' => $id));
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $conditions, true);
        if (empty($cluster)) {
            throw new NotFoundException('Invalid galaxy cluster');
        }
        $cluster = $cluster[0];
        $existingRelations = $this->GalaxyCluster->GalaxyClusterRelation->getExistingRelationships();
        $cluster = $this->GalaxyCluster->attachClusterToRelations($this->Auth->user(), $cluster);

        App::uses('ClusterRelationsTreeTool', 'Tools');
        $grapher = new ClusterRelationsTreeTool();
        $grapher->construct($this->Auth->user(), $this->GalaxyCluster);
        $tree = $grapher->getTree($cluster);

        $this->set('existingRelations', $existingRelations);
        $this->set('cluster', $cluster);
        $relations = $this->GalaxyCluster->GalaxyClusterRelation->fetchRelations($this->Auth->user(), array(
            'conditions' => array(
                'GalaxyClusterRelation.galaxy_cluster_uuid' => $cluster['GalaxyCluster']['uuid']
            ),
            'contain' => array('SharingGroup', 'TargetCluster', 'GalaxyClusterRelationTag' => array('Tag'))
        ));
        $this->set('relations', $relations);
        $this->set('tree', $tree);
        $this->loadModel('Attribute');
        $distributionLevels = $this->Attribute->distributionLevels;
        unset($distributionLevels[4]);
        unset($distributionLevels[5]);
        $this->set('distributionLevels', $distributionLevels);
    }

    public function viewRelationTree($clusterId)
    {
        $options = array('conditions' => array('GalaxyCluster.id' => $clusterId));
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), $options, true);
        if (empty($cluster)) {
            throw new NotFoundException('Invalid galaxy cluster');
        }
        $cluster = $cluster[0];
        $cluster = $this->GalaxyCluster->attachClusterToRelations($this->Auth->user(), $cluster);
        App::uses('ClusterRelationsTreeTool', 'Tools');
        $grapher = new ClusterRelationsTreeTool();
        $grapher->construct($this->Auth->user(), $this->GalaxyCluster);
        $tree = $grapher->getTree($cluster);
        $this->set('tree', $tree);
        $this->render('/Elements/GalaxyClusters/view_relation_tree');
    }
}
