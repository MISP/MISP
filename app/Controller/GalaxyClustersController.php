<?php
App::uses('AppController', 'Controller');

/**
 * @property GalaxyCluster $GalaxyCluster
 */
class GalaxyClustersController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'recursive' => -1,
            'order' => array(
                'GalaxyCluster.version' => 'DESC',
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

    public function index($galaxyId)
    {
        $filters = $this->IndexFilter->harvestParameters(array('context', 'searchall'));
        $aclConditions = $this->GalaxyCluster->buildConditions($this->Auth->user());
        $contextConditions = array();
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        } else {
            $contextConditions = array('GalaxyCluster.deleted' => false);
        }

        if ($filters['context'] == 'default') {
                $contextConditions['GalaxyCluster.default'] = true;
        } elseif ($filters['context'] == 'custom') {
            $contextConditions['GalaxyCluster.default'] = false;
        } elseif ($filters['context'] == 'org') {
            $contextConditions['GalaxyCluster.org_id'] = $this->Auth->user('org_id');
        } elseif ($filters['context'] == 'deleted') {
            $contextConditions['GalaxyCluster.deleted'] = true;
        }

        $this->set('passedArgs', json_encode(array('context' => $filters['context'], 'searchall' => isset($filters['searchall']) ? $filters['searchall'] : '')));
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
        $searchConditions['GalaxyCluster.galaxy_id'] = $galaxyId;

        if ($this->_isRest()) {
            $clusters = $this->GalaxyCluster->find(
                'all',
                array(
                    'conditions' => array(
                        'AND' => array($contextConditions, $searchConditions, $aclConditions)
                    ),
                )
            );
            return $this->RestResponse->viewData($clusters, $this->response->type());
        }

        $this->paginate['conditions']['AND'][] = $contextConditions;
        $this->paginate['conditions']['AND'][] = $searchConditions;
        $this->paginate['conditions']['AND'][] = $aclConditions;
        $this->paginate['contain'] = array_merge($this->paginate['contain'], array('Org', 'Orgc', 'SharingGroup', 'GalaxyClusterRelation', 'TargetingClusterRelation'));
        $clusters = $this->paginate();

        $this->GalaxyCluster->attachExtendByInfo($this->Auth->user(), $clusters);

        $tagIds = array();
        foreach ($clusters as $k => $cluster) {
            $clusters[$k] = $this->GalaxyCluster->attachExtendFromInfo($this->Auth->user(), $clusters[$k]);
            $clusters[$k]['GalaxyCluster']['relation_counts'] = array(
                'out' => count($clusters[$k]['GalaxyClusterRelation']),
                'in' => count($clusters[$k]['TargetingClusterRelation']),
            );

            if (isset($cluster['Tag']['id'])) {
                $tagIds[] = $cluster['Tag']['id'];
                $clusters[$k]['GalaxyCluster']['tag_id'] = $cluster['Tag']['id'];
            }
            $clusters[$k]['GalaxyCluster']['synonyms'] = array();
            foreach ($cluster['GalaxyElement'] as $element) {
                $clusters[$k]['GalaxyCluster']['synonyms'][] = $element['value'];
            }
            $clusters[$k]['GalaxyCluster']['event_count'] = 0; // real number is assigned later
        }

        $eventCountsForTags = $this->GalaxyCluster->Tag->EventTag->countForTags($tagIds, $this->Auth->user());

        $this->loadModel('Sighting');
        $csvForTags = $this->Sighting->tagsSparkline($tagIds, $this->Auth->user(), '0');
        foreach ($clusters as $k => $cluster) {
            if (isset($cluster['GalaxyCluster']['tag_id'])) {
                if (isset($csvForTags[$cluster['GalaxyCluster']['tag_id']])) {
                    $clusters[$k]['csv'] = $csvForTags[$cluster['GalaxyCluster']['tag_id']];
                }
                if (isset($eventCountsForTags[$cluster['GalaxyCluster']['tag_id']])) {
                    $clusters[$k]['GalaxyCluster']['event_count'] = $eventCountsForTags[$cluster['GalaxyCluster']['tag_id']];
                }
            }
        }
        $customClusterCount = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), [
            'count' => true,
            'conditions' => [
                'AND' => [$searchConditions, $aclConditions],
                'GalaxyCluster.default' => 0,
            ]
        ]);
        $this->loadModel('Attribute');
        $distributionLevels = $this->Attribute->distributionLevels;
        unset($distributionLevels[5]);
        $this->set('distributionLevels', $distributionLevels);
        $this->set('list', $clusters);
        $this->set('galaxy_id', $galaxyId);
        $this->set('custom_cluster_count', $customClusterCount);

        if ($this->request->is('ajax')) {
            $this->layout = 'ajax';
            $this->render('ajax/index');
        }
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function view($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'view', $throwErrors=true, $full=true);
        $tag = $this->GalaxyCluster->Tag->find('first', array(
            'conditions' => array(
                'LOWER(name)' => strtolower($cluster['GalaxyCluster']['tag_name']),
            ),
            'fields' => array('id'),
            'recursive' => -1,
            'contain' => array('EventTag.event_id')
        ));
        if (!empty($tag)) {
            $cluster['GalaxyCluster']['tag_count'] = $this->GalaxyCluster->Tag->EventTag->countForTag($tag['Tag']['id'], $this->Auth->user());
            $cluster['GalaxyCluster']['tag_id'] = $tag['Tag']['id'];
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($cluster, $this->response->type());
        } else {
            $clusters = [$cluster];
            $this->GalaxyCluster->attachExtendByInfo($this->Auth->user(), $clusters);
            $cluster = $clusters[0];
            $cluster = $this->GalaxyCluster->attachExtendFromInfo($this->Auth->user(), $cluster);
            $this->set('id', $id);
            $this->set('galaxy', ['Galaxy' => $cluster['GalaxyCluster']['Galaxy']]);
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
            if (!$cluster['GalaxyCluster']['default'] && !$cluster['GalaxyCluster']['published'] && $cluster['GalaxyCluster']['orgc_id'] == $this->Auth->user()['org_id']) {
                $this->Flash->warning(__('This cluster is not published. Users will not be able to use it'));
            }
        }
    }

    /**
     * @param  mixed $galaxyId ID of the galaxy to which the cluster will be added
     */
    public function add($galaxyId)
    {
        if (Validation::uuid($galaxyId)) {
            $temp = $this->GalaxyCluster->Galaxy->find('first', array(
                'recursive' => -1,
                'fields' => array('Galaxy.id', 'Galaxy.uuid'),
                'conditions' => array('Galaxy.uuid' => $galaxyId)
            ));
            if ($temp === null) {
                throw new NotFoundException(__('Invalid galaxy'));
            }
            $galaxyId = $temp['Galaxy']['id'];
        } elseif (!is_numeric($galaxyId)) {
            throw new NotFoundException(__('Invalid galaxy'));
        }
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
            $forkedCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
                'conditions' => array('GalaxyCluster.uuid' => $forkUuid),
            ), true);
            if (!empty($forkedCluster)) {
                $forkedCluster = $forkedCluster[0];
                $forkedClusterMeta = $forkedCluster['GalaxyCluster'];
                if (empty($this->request->data)) {
                    $this->request->data = $forkedCluster;
                    unset($this->request->data['GalaxyCluster']['id']);
                    unset($this->request->data['GalaxyCluster']['uuid']);
                    foreach ($forkedCluster['GalaxyCluster']['GalaxyElement'] as $k => $element) {
                        unset($forkedCluster['GalaxyCluster']['GalaxyElement'][$k]['id']);
                        unset($forkedCluster['GalaxyCluster']['GalaxyElement'][$k]['galaxy_cluster_id']);
                    }
                    $this->request->data['GalaxyCluster']['extends_uuid'] = $forkedCluster['GalaxyCluster']['uuid'];
                    $this->request->data['GalaxyCluster']['extends_version'] = $forkedCluster['GalaxyCluster']['version'];
                    $this->request->data['GalaxyCluster']['elements'] = json_encode($forkedCluster['GalaxyCluster']['GalaxyElement']);
                    $this->request->data['GalaxyCluster']['elementsDict'] = $forkedCluster['GalaxyCluster']['GalaxyElement'];
                    $this->request->data['GalaxyCluster']['authors'] = json_encode($forkedCluster['GalaxyCluster']['authors']);
                }
                unset($forkedClusterMeta['Galaxy']);
                unset($forkedClusterMeta['Org']);
                unset($forkedClusterMeta['Orgc']);
                $this->set('forkedCluster', $forkedCluster);
                $this->set('forkedClusterMeta', $forkedClusterMeta);
            } else {
                throw new NotFoundException('Forked cluster not found.');
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $cluster = $this->request->data;
            if (!isset($cluster['GalaxyCluster'])) {
                $cluster = array('GalaxyCluster' => $cluster);
            }
            $cluster['GalaxyCluster']['galaxy_id'] = $galaxyId;
            $cluster['GalaxyCluster']['published'] = false;
            $errors = array();
            if (empty($cluster['GalaxyCluster']['elements'])) {
                if (empty($cluster['GalaxyCluster']['GalaxyElement'])) {
                    $cluster['GalaxyCluster']['GalaxyElement'] = array();
                }
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['elements'], true);
                if (is_null($decoded)) {
                    $this->GalaxyCluster->validationErrors['values'][] = __('Invalid JSON');
                    $errors[] = sprintf(__('Invalid JSON'));
                }
                $cluster['GalaxyCluster']['GalaxyElement'] = $decoded;
            }
            if (!empty($cluster['GalaxyCluster']['extends_uuid'])) {
                $extendId = $this->Toolbox->findIdByUuid($this->GalaxyCluster, $cluster['GalaxyCluster']['extends_uuid']);
                $forkedCluster = $this->GalaxyCluster->fetchGalaxyClusters(
                    $this->Auth->user(),
                    array('conditions' => array('GalaxyCluster.id' => $extendId))
                );
                if (!empty($forkedCluster)) {
                    $cluster['GalaxyCluster']['extends_uuid'] = $forkedCluster[0]['GalaxyCluster']['uuid'];
                    if (empty($cluster['GalaxyCluster']['extends_version'])) {
                        $cluster['GalaxyCluster']['extends_version'] = $forkedCluster[0]['GalaxyCluster']['version'];
                    }
                } else {
                    $cluster['GalaxyCluster']['extends_uuid'] = null;
                }
            } else {
                $cluster['GalaxyCluster']['extends_uuid'] = null;
            }
            $errors = $this->GalaxyCluster->saveCluster($this->Auth->user(), $cluster);
            if (!empty($errors)) {
                $message = implode(', ', $errors);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'add', $this->GalaxyCluster->id, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                $message = __('Galaxy cluster saved');
                if ($this->request->is('ajax')) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'add', $this->GalaxyCluster->id, $this->response->type());
                } else if ($this->_isRest()) {
                    $saved_cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $this->GalaxyCluster->id, 'view', $throwErrors=true, $full=true);
                    return $this->RestResponse->viewData($saved_cluster);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $this->GalaxyCluster->id));
                }
            }
        }
        $this->set('galaxy_id', $galaxyId);
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'add');
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function edit($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=true);
        if ($cluster['GalaxyCluster']['default']) {
            throw new MethodNotAllowedException('Default galaxy cluster cannot be edited');
        }
        $this->GalaxyCluster->data = array('GalaxyCluster' => $cluster['GalaxyCluster'], 'GalaxyElement' => $cluster['GalaxyCluster']['GalaxyElement']);

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

        if (!empty($cluster['GalaxyCluster']['extends_uuid'])) {
            $forkedCluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
                'conditions' => array('uuid' => $cluster['GalaxyCluster']['extends_uuid']),
            ), false);
        } else {
            $forkedCluster = array();
        }

        if (!empty($forkedCluster)) {
            $forkedCluster = $forkedCluster[0];
            $this->set('forkUuid', $cluster['GalaxyCluster']['extends_uuid']);
            $forkedClusterMeta = $forkedCluster['GalaxyCluster'];
            $this->set('forkedCluster', $forkedCluster);
            $this->set('forkedClusterMeta', $forkedClusterMeta);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $cluster = $this->request->data;
            if (!isset($cluster['GalaxyCluster'])) {
                $cluster = array('GalaxyCluster' => $cluster);
            }
            $errors = array();
            if (!isset($cluster['GalaxyCluster']['uuid'])) {
                $cluster['GalaxyCluster']['uuid'] = $this->GalaxyCluster->data['GalaxyCluster']['uuid']; // freeze the uuid
            }
            if (!isset($cluster['GalaxyCluster']['id'])) {
                $cluster['GalaxyCluster']['id'] = $id;
            }

            if (empty($cluster['GalaxyCluster']['elements'])) {
                if (empty($cluster['GalaxyCluster']['GalaxyElement'])) {
                    $cluster['GalaxyCluster']['GalaxyElement'] = array();
                }
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['elements'], true);
                if (is_null($decoded)) {
                    $this->GalaxyCluster->validationErrors['values'][] = __('Invalid JSON');
                    $errors[] = sprintf(__('Invalid JSON'));
                }
                $cluster['GalaxyCluster']['GalaxyElement'] = $decoded;
            }

            if (empty($cluster['GalaxyCluster']['authors'])) {
                $cluster['GalaxyCluster']['authors'] = [];
            } else if (is_array($cluster['GalaxyCluster']['authors'])) {
                // This is as intended, move on
            }else {
                $decoded = json_decode($cluster['GalaxyCluster']['authors'], true);
                if (is_null($decoded)) { // authors might be comma separated
                    $decoded = array_map('trim', explode(',', $cluster['GalaxyCluster']['authors']));
                }
                $cluster['GalaxyCluster']['authors'] = $decoded;
            }
            $cluster['GalaxyCluster']['authors'] = json_encode($cluster['GalaxyCluster']['authors']);
            $cluster['GalaxyCluster']['published'] = false;
            if (!empty($errors)) {
                $message = implode(', ', $errors);
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'edit', $cluster['GalaxyCluster']['id'], $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                $errors = $this->GalaxyCluster->editCluster($this->Auth->user(), $cluster);
                if (!empty($errors)) {
                    $message = implode(', ', $errors);
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('GalaxyCluster', 'edit', $cluster['GalaxyCluster']['id'], $message, $this->response->type());
                    } else {
                        $this->Flash->error($message);
                    }
                } else {
                    $message = __('Galaxy cluster saved');
                    if ($this->request->is('ajax')) {
                        return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'edit', $cluster['GalaxyCluster']['id'], $this->response->type());
                    } else if ($this->_isRest()) {
                        $saved_cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'view', $throwErrors=true, $full=true);
                        return $this->RestResponse->viewData($saved_cluster);
                    } else {
                        $this->Flash->success($message);
                        $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $this->GalaxyCluster->id));
                    }
                }
            }
        } else {
            $this->GalaxyCluster->data['GalaxyCluster']['elements'] = json_encode($this->GalaxyCluster->data['GalaxyElement']);
            $this->GalaxyCluster->data['GalaxyCluster']['elementsDict'] = $this->GalaxyCluster->data['GalaxyElement'];
            $this->GalaxyCluster->data['GalaxyCluster']['authors'] = !empty($this->GalaxyCluster->data['GalaxyCluster']['authors']) ? json_encode($this->GalaxyCluster->data['GalaxyCluster']['authors']) : '';
            $this->request->data = $this->GalaxyCluster->data;
        }
        $fieldDesc = array(
            'authors' => __('Valid JSON array or comma separated'),
            'elements' => __('Valid JSON array composed from Object of the form {key: keyname, value: actualValue}'),
            'distribution' => Hash::extract($this->Attribute->distributionDescriptions, '{n}.formdesc'),
        );
        $this->set('id', $cluster['GalaxyCluster']['id']);
        $this->set('cluster', $cluster);
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

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function publish($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'publish', $throwErrors=true, $full=false);
        if ($cluster['GalaxyCluster']['published']) {
            throw new MethodNotAllowedException(__('You can\'t publish a galaxy cluster that is already published'));
        }
        if ($cluster['GalaxyCluster']['default']) {
            throw new MethodNotAllowedException(__('Default galaxy cluster cannot be published'));
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $success = $this->GalaxyCluster->publishRouter($this->Auth->user(), $cluster, $passAlong=null);
            if (Configure::read('MISP.background_jobs')) {
                $message = __('Publish job queued. Job ID: %s', $success);
                $this->Flash->success($message);
                if ($this->_isRest()) {
                    return $this->RestResponse->viewData(array('message' => $message), $this->response->type());
                }
            } else {
                if (!$success) {
                    $message = __('Could not publish galaxy cluster');
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveFailResponse('GalaxyCluster', 'publish', $cluster['GalaxyCluster']['id'], $message, $this->response->type());
                    } else {
                        $this->Flash->error($message);
                    }
                } else {
                    $message = __('Galaxy cluster published');
                    if ($this->_isRest()) {
                        return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'publish', $cluster['GalaxyCluster']['id'], $this->response->type());
                    } else {
                        $this->Flash->success($message);
                    }
                }
            }
            $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $cluster['GalaxyCluster']['id']));
        } else {
            $this->set('cluster', $cluster);
            $this->set('type', 'publish');
            $this->render('ajax/publishConfirmationForm');
        }
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function unpublish($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'publish', $throwErrors=true, $full=false);
        if (!$cluster['GalaxyCluster']['published']) {
            throw new MethodNotAllowedException(__('You can\'t unpublish a galaxy cluster that is not published'));
        }
        if ($cluster['GalaxyCluster']['default']) {
            throw new MethodNotAllowedException(__('Default galaxy cluster cannot be unpublished'));
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $success = $this->GalaxyCluster->unpublish($cluster);
            if (!$success) {
                $message = __('Could not unpublish galaxy cluster');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'unpublish', $cluster['GalaxyCluster']['id'], $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                $message = __('Galaxy cluster unpublished');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'unpublish', $cluster['GalaxyCluster']['id'], $this->response->type());
                } else {
                    $this->Flash->success($message);
                }
            }
            $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $cluster['GalaxyCluster']['id']));
        } else {
            $this->set('cluster', $cluster);
            $this->set('type', 'unpublish');
            $this->render('ajax/publishConfirmationForm');
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

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function delete($id, $hard=false)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'delete', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            if (!empty($this->request->data['hard'])) {
                $hard = true;
            }
            $result = $this->GalaxyCluster->deleteCluster($cluster['GalaxyCluster']['id'], $hard=$hard);
            $galaxyId = $cluster['GalaxyCluster']['galaxy_id'];
            if ($result) {
                $message = __(
                    'Galaxy cluster successfuly %s deleted%s.',
                    $hard ? __('hard') : __('soft'),
                    $hard ? __(' and added to the block list') : ''
                );
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'delete', $cluster['GalaxyCluster']['id'], $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'galaxies', 'action' => 'view', $galaxyId));
                }
            } else {
                $message = __('Galaxy cluster could not be %s deleted.', $hard ? __('hard') : __('soft'));
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'delete', $cluster['GalaxyCluster']['id'], $message, $this->response->type(), $message);
                } else {
                    $this->Flash->error($message);
                    $this->redirect(array('controller' => 'galaxies', 'action' => 'view', $galaxyId));
                }
            }
        } else {
            if ($this->request->is('ajax')) {
                $this->set('id', $cluster['GalaxyCluster']['id']);
                $this->set('cluster', $cluster['GalaxyCluster']);
                $this->render('ajax/galaxy_cluster_delete_confirmation');
            } else {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            }
        }
    }

    public function restore($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'delete', $throwErrors=true, $full=false);
        if ($this->request->is('post')) {
            $result = $this->GalaxyCluster->restoreCluster($cluster['GalaxyCluster']['id']);
            $galaxyId = $cluster['GalaxyCluster']['galaxy_id'];
            if ($result) {
                $message = __('Galaxy cluster successfuly restored.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'restore', $cluster['GalaxyCluster']['id'], $this->response->type());
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'galaxies', 'action' => 'view', $galaxyId));
                }
            } else {
                $message = __('Galaxy cluster could not be %s restored.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'restore', $cluster['GalaxyCluster']['id'], $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect(array('controller' => 'galaxies', 'action' => 'view', $galaxyId));
                }
            }
        } else {
            throw new MethodNotAllowedException(__('This function can only be reached via POST.'));
        }
    }

    public function viewCyCatRelations($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'view', true, false);
        $CyCatRelations = $this->GalaxyCluster->getCyCatRelations($cluster);
        $this->set('cluster', $cluster);
        $this->set('CyCatRelations', $CyCatRelations);
        $this->render('cluster_cycatrelations');
    }

    public function viewGalaxyMatrix($id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be reached via AJAX.');
        }

        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array(
            'conditions' => array('id' => $id)
        ), $full=false);
        if (empty($cluster)) {
            throw new MethodNotAllowedException("Invalid Galaxy Cluster.");
        }
        $cluster = $cluster[0];
        $this->loadModel('Event');
        $mitreAttackGalaxyId = $this->GalaxyCluster->Galaxy->getMitreAttackGalaxyId();
        if ($mitreAttackGalaxyId == 0) { // Mitre Att&ck galaxy not found
            return new CakeResponse(array('body' => '', 'status' => 200, 'type' => 'text'));
        }
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
            'group' => array('Tag.name', 'Tag.id')
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
            'group' => array('Tag.name', 'Tag.id')
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

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function updateCluster($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'edit', $throwErrors=true, $full=true);
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
            if (!empty($this->request->data['GalaxyCluster'])) {
                foreach ($this->request->data['GalaxyCluster'] as $k => $jElement) {
                    $element = json_decode($jElement, true);
                    if (!is_null($element) && $element != 0) {
                        $elements[] = array(
                                'key' => $element['key'],
                                'value' => $element['value'],
                            );
                    }
                }
            }
            $cluster['GalaxyCluster']['GalaxyElement'] = $elements;
            $cluster['GalaxyCluster']['extends_version'] = $parentVersion;
            $cluster['GalaxyCluster']['published'] = false;
            $errors = $this->GalaxyCluster->editCluster($this->Auth->user(), $cluster, $fieldList=array('extends_version', 'published'), $deleteOldElements=false);
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', $errors);
                $this->Flash->error($flashErrorMessage);
            } else {
                $this->Flash->success(__('Cluster updated to the newer version'));
                $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $id));
            }
        }
        $missingElements = array();
        foreach ($parentCluster['GalaxyCluster']['GalaxyElement'] as $k => $parentElement) {
            $found = false;
            foreach ($cluster['GalaxyCluster']['GalaxyElement'] as $k => $clusterElement) {
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
        $this->set('parentElements', $parentCluster['GalaxyCluster']['GalaxyElement']);
        $this->set('clusterElements', $cluster['GalaxyCluster']['GalaxyElement']);
        $this->set('forkVersion', $forkVersion);
        $this->set('parentVersion', $parentVersion);
        $this->set('newVersionAvailable', $parentVersion > $forkVersion);
        $this->set('id', $cluster['GalaxyCluster']['id']);
        $this->set('galaxy_id', $cluster['GalaxyCluster']['galaxy_id']);
        $this->set('defaultCluster', $cluster['GalaxyCluster']['default']);
        $this->set('cluster', $cluster);
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function viewRelations($id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be reached via AJAX.');
        }
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'view', true, true);
        $existingRelations = $this->GalaxyCluster->GalaxyClusterRelation->getExistingRelationships();
        $cluster = $this->GalaxyCluster->attachClusterToRelations($this->Auth->user(), $cluster);

        App::uses('ClusterRelationsTreeTool', 'Tools');
        $grapher = new ClusterRelationsTreeTool();
        $grapher->construct($this->Auth->user(), $this->GalaxyCluster);
        $tree = $grapher->getTree($cluster);

        $this->set('existingRelations', $existingRelations);
        $this->set('cluster', $cluster);
        $relations = $cluster['GalaxyCluster']['GalaxyClusterRelation'];
        $this->set('passedArgs', json_encode([]));
        $this->set('relations', $relations);
        $this->set('tree', $tree);
        $this->loadModel('Attribute');
        $distributionLevels = $this->Attribute->distributionLevels;
        unset($distributionLevels[4]);
        unset($distributionLevels[5]);
        $this->set('distributionLevels', $distributionLevels);
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function viewRelationTree($id)
    {
        $cluster = $this->GalaxyCluster->fetchIfAuthorized($this->Auth->user(), $id, 'view', $throwErrors=true, $full=true);
        $cluster = $this->GalaxyCluster->attachClusterToRelations($this->Auth->user(), $cluster);
        App::uses('ClusterRelationsTreeTool', 'Tools');
        $grapher = new ClusterRelationsTreeTool();
        $grapher->construct($this->Auth->user(), $this->GalaxyCluster);
        $tree = $grapher->getTree($cluster);
        $this->set('tree', $tree);
        $this->render('/Elements/GalaxyClusters/view_relation_tree');
    }
}
