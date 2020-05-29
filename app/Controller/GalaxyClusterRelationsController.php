<?php
App::uses('AppController', 'Controller');

class GalaxyClusterRelationsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'recursive' => -1,
    );

    public function index()
    {
        $filters = $this->IndexFilter->harvestParameters(array('context', 'searchall'));
        $aclConditions = $this->GalaxyClusterRelation->buildConditions($this->Auth->user());
        $contextConditions = array();
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        } else {
            $contextConditions = array();
            if ($filters['context'] == 'default') {
                $contextConditions = array(
                    'GalaxyClusterRelation.default' => true
                );
            } elseif ($filters['context'] == 'custom') {
                $contextConditions = array(
                    'GalaxyClusterRelation.default' => false
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
            $searchConditions = array(
                'OR' => array(
                    'LOWER(GalaxyClusterRelation.referenced_galaxy_cluster_type) LIKE' => $searchall,
                    'LOWER(GalaxyCluster.value) LIKE' => $searchall,
                    'LOWER(ReferencedGalaxyCluster.value) LIKE' => $searchall,
                    'LOWER(GalaxyCluster.tag_name) LIKE' => $searchall,
                    'LOWER(ReferencedGalaxyCluster.tag_name) LIKE' => $searchall,
                ),
            );
        }

        if ($this->_isRest()) {
            $relations = $this->GalaxyClusterRelation->find('all', 
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($contextConditions, $searchConditions, $aclConditions)
                    ),
                    'contain' => array('SharingGroup', 'SourceCluster', 'TargetCluster', 'GalaxyClusterRelationTag' => array('Tag'))
                )
            );
            return $this->RestResponse->viewData($relations, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $contextConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $this->paginate['contain'] = array('SharingGroup', 'SourceCluster', 'TargetCluster', 'GalaxyClusterRelationTag' => array('Tag'));
            $relations = $this->paginate();
            $this->loadModel('SharingGroup');
            $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
            $this->loadModel('Attribute');
            $distributionLevels = $this->Attribute->distributionLevels;
            unset($distributionLevels[5]);
            $this->set('distributionLevels', $distributionLevels);
            $this->set('data', $relations);
        }
    }

    public function add()
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

        if ($this->request->is('post')) {
            if (empty($this->request->data['GalaxyClusterRelation'])) {
                $this->request->data = array('GalaxyClusterRelation' => $this->request->data);
            }
            $relation = $this->request->data;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusters = $this->fetchClustersFromRelation($relation);
            $clusterSource = $clusters['clusterSource'];
            $clusterTarget = $clusters['clusterTarget'];

            $errors = array();
            if (!$this->Auth->user()['Role']['perm_galaxy_editor']) {
                $errors = array(__('Invalid permssions'));
            }

            if ($this->Auth->user()['Role']['perm_site_admin'] || $clusterSource['GalaxyCluster']['org_id'] != $this->Auth->user()['org_id']) {
                $errors = $this->GalaxyClusterRelation->saveRelation($this->Auth->user(), $relation);
            } else {
                $errors = array(__('Only the owner organisation of the source cluster can use it as a source'));
            }

            $message = empty($errors) ? __('Relationship added.') : __('Relationship could not be added.');
            if ($this->_isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'add', $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'add', $message, $this->response->type());
                }
            } elseif ($this->request->is('ajax')) {
                $this->autoRender = false;
                if (empty($errors)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => '')),'status' => 200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Could not save relation, reason: ' . json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors)))),'status' => 200, 'type' => 'json'));
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    $this->redirect($this->referer());
                } else {
                    $message .= __(' Reason: %s', json_encode($this->GalaxyClusterRelation->validationErrors, true));
                    $this->Flash->error($message);
                }
            }
        }
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'add');
    }

    public function edit($id)
    {
        $conditions = array('conditions' => array('GalaxyClusterRelation.id' => $id), 'contain' => array('GalaxyClusterRelationTag' => 'Tag'));
        $existingRelation = $this->GalaxyClusterRelation->fetchRelations($this->Auth->user(), $conditions);
        if (empty($existingRelation)) {
            throw new NotFoundException(__('Invalid cluster relation'));
        }
        $existingRelation = $existingRelation[0];
        $id = $existingRelation['GalaxyClusterRelation']['id'];
        if ($existingRelation['GalaxyClusterRelation']['default']) {
            throw new MethodNotAllowedException(__('Default cluster relation cannot be edited'));
        }

        $existingRelation['GalaxyClusterRelation']['tags'] = Hash::extract($existingRelation['GalaxyClusterRelationTag'], '{n}.Tag.name');
        $existingRelation['GalaxyClusterRelation']['tags'] = implode(', ', $existingRelation['GalaxyClusterRelation']['tags']);

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

        if ($this->request->is('post') || $this->request->is('put')) {
            $relation = $this->request->data;
            $relation['GalaxyClusterRelation']['id'] = $id;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusters = $this->fetchClustersFromRelation($relation);
            $clusterSource = $clusters['clusterSource'];

            $errors = array();
            if (!$this->Auth->user()['Role']['perm_galaxy_editor']) {
                $errors = array(__('Invalid permssions'));
            }

            if (!empty($relation['GalaxyClusterRelation']['tags'])) {
                $tags = explode(',', $relation['GalaxyClusterRelation']['tags']);
                $tags = array_map('trim', $tags);
                $relation['GalaxyClusterRelation' ]['tags'] = $tags;
            }

            if ($this->Auth->user()['Role']['perm_site_admin'] || $clusterSource['GalaxyCluster']['org_id'] != $this->Auth->user()['org_id']) {
                $errors = $this->GalaxyClusterRelation->editRelation($this->Auth->user(), $relation);
            } else {
                $errors = array(__('Only the owner organisation of the source cluster can use it as a source'));
            }

            $message = empty($errors) ? __('Relationship saved.') : __('Relationship could not be edited.');
            if ($this->_isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'edit', $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'edit', $message, $this->response->type());
                }if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                    $errors[] = array(__('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to edit it.'));
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    // $this->redirect(array('action' => 'index'));
                    $this->redirect($this->referer());
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors), true));
                    $this->Flash->error($message);
                }
            }
        }
        $this->request->data = $existingRelation;
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'edit');
        $this->render('add');
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $relation = $this->GalaxyClusterRelation->fetchRelations($this->Auth->user(), array('conditions' => array('id' => $id)));
            if (empty($relation)) {
                throw new NotFoundException('Target cluster not found.');
            }
            $result = $this->GalaxyClusterRelation->delete($id, true);
            if ($result) {
                $message = 'Galaxy cluster relationship successfuly deleted.';
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'delete', $id, $this->response->type());
                } else {
                    $this->Flash->success($message);
                    $this->redirect($this->referer());
                }
            } else {
                $message = 'Galaxy cluster relationship could not be deleted.';
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'delete', $id, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect($this->referer());
                }
            }
        }
    }

    public function fetchClustersFromRelation($relation)
    {
        // Fetch cluster source and adapt IDs
        $conditions = array();
        $conditions['uuid'] = $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'];
        $clusterSource = $this->GalaxyClusterRelation->SourceCluster->fetchGalaxyClusters($this->Auth->user(), array('conditions' => $conditions), false);
        if (empty($clusterSource)) {
            throw new NotFoundException('Source cluster not found.');
        }
        $clusterSource = $clusterSource[0];

        // Fetch cluster target and adapt IDs
        $conditions['uuid'] = $relation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'];
        $clusterTarget = $this->GalaxyClusterRelation->TargetCluster->fetchGalaxyClusters($this->Auth->user(), array('conditions' => $conditions), false);
        if (empty($clusterTarget)) {
            throw new NotFoundException('Target cluster not found.');
        }
        $clusterTarget = $clusterTarget[0];
        return array(
            'clusterSource' => $clusterSource,
            'clusterTarget' => $clusterTarget,
            'relation' => $relation,
        );
    }
}