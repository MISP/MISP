<?php
App::uses('AppController', 'Controller');

/**
 * @property GalaxyClusterRelation $GalaxyClusterRelation
 */
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
                    'LOWER(TargetCluster.value) LIKE' => $searchall,
                    'LOWER(TargetCluster.tag_name) LIKE' => $searchall,
                    'LOWER(SourceCluster.value) LIKE' => $searchall,
                    'LOWER(SourceCluster.tag_name) LIKE' => $searchall,
                ),
            );
        }

        if ($this->_isRest()) {
            $relations = $this->GalaxyClusterRelation->find(
                'all',
                array(
                    'recursive' => -1,
                    'conditions' => array(
                        'AND' => array($contextConditions, $searchConditions, $aclConditions)
                    ),
                    'contain' => array('SharingGroup', 'SourceCluster', 'TargetCluster', 'GalaxyClusterRelationTag' => array('Tag'))
                )
            );
            $relations = $this->GalaxyClusterRelation->removeNonAccessibleTargetCluster($this->Auth->user(), $relations);
            return $this->RestResponse->viewData($relations, $this->response->type());
        } else {
            $this->paginate['conditions']['AND'][] = $contextConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $this->paginate['contain'] = array('SharingGroup', 'SourceCluster' => ['Org', 'Orgc'], 'TargetCluster', 'GalaxyClusterRelationTag' => array('Tag'));
            $relations = $this->paginate();
            $relations = $this->GalaxyClusterRelation->removeNonAccessibleTargetCluster($this->Auth->user(), $relations);
            $this->loadModel('MispAttribute');
            $distributionLevels = $this->MispAttribute->distributionLevels;
            unset($distributionLevels[5]);
            $this->set('distributionLevels', $distributionLevels);
            $this->set('data', $relations);
        }
    }

    public function view($id)
    {
        if ($this->_isRest()) {
            $conditions = array('GalaxyClusterRelation.id' => $id);
            $relation = $this->GalaxyClusterRelation->fetchRelations($this->Auth->user(), array(
                'conditions' => $conditions,
                'contain' => array('SharingGroup', 'TargetCluster', 'GalaxyClusterRelationTag' => array('Tag'))
            ));
            if (empty($relation)) {
                throw new NotFoundException(__('Invalid cluster relation'));
            }
            $relation = $relation[0];
            if (!empty($relation['GalaxyClusterRelationTag'])) {
                foreach ($relation['GalaxyClusterRelationTag'] as $relationTag) {
                    $relation['Tag'][] = $relationTag['Tag'];
                }
            }
            unset($relation['GalaxyClusterRelationTag']);
            return $this->RestResponse->viewData($relation, $this->response->type());
        } else {
            throw new MethodNotAllowedException(__('This method can only be accessed via RestSearch.'));
        }
    }

    public function add()
    {
        $this->loadModel('MispAttribute');
        $distributionLevels = $this->MispAttribute->distributionLevels;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->loadModel('SharingGroup');
        $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);

        if ($this->request->is('post')) {
            $errors = array();
            if (empty($this->request->data['GalaxyClusterRelation'])) {
                $this->request->data = array('GalaxyClusterRelation' => $this->request->data);
            }
            $relation = $this->request->data;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusterSource = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], array('edit', 'publish'), $throwErrors=false, $full=false);
            if (isset($clusterSource['authorized']) && !$clusterSource['authorized']) {
                $errors = array($clusterSource['error']);
            }

            if (!empty($relation['GalaxyClusterRelation']['tags'])) {
                $tags = explode(',', $relation['GalaxyClusterRelation']['tags']);
                $tags = array_map('trim', $tags);
                $relation['GalaxyClusterRelation' ]['tags'] = $tags;
            } else {
                $relation['GalaxyClusterRelation' ]['tags'] = array();
            }

            if (empty($errors)) {
                $errors = $this->GalaxyClusterRelation->saveRelation($this->Auth->user(), $clusterSource['SourceCluster'], $relation);
            }

            if (empty($errors)) {
                $message = __('Relationship added.');
                $this->GalaxyClusterRelation->SourceCluster->touchTimestamp($clusterSource['SourceCluster']['id']);
                $this->GalaxyClusterRelation->SourceCluster->unpublish($clusterSource['SourceCluster']['id']);
            } else {
                $message = __('Relationship could not be added.');
            }
            if ($this->_isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'add', $this->response->type(), $message);
                } else {
                    $message .= sprintf('Reasons: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors)));
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'add', $message, $this->response->type());
                }
            } elseif ($this->request->is('ajax')) {
                $this->autoRender = false;
                if (empty($errors)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => '')),'status' => 200, 'type' => 'json'));
                } else {
                    $message .= sprintf('Reasons: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors)));
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $message)),'status' => 200, 'type' => 'json'));
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'index'));
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors)));
                    $this->Flash->error($message);
                }
            }
        }
        $this->set('existingRelations', $this->GalaxyClusterRelation->getExistingRelationships());
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

        $this->loadModel('MispAttribute');
        $distributionLevels = $this->MispAttribute->distributionLevels;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $this->loadModel('SharingGroup');
        $sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);

        if ($this->request->is('post') || $this->request->is('put')) {
            $errors = array();
            if (empty($this->request->data['GalaxyClusterRelation'])) {
                $this->request->data = array('GalaxyClusterRelation' => $this->request->data);
            }
            $relation = $this->request->data;
            $relation['GalaxyClusterRelation']['id'] = $id;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusterSource = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], array('edit', 'publish'), $throwErrors=false, $full=false);
            if (isset($clusterSource['authorized']) && !$clusterSource['authorized']) {
                $errors = array($clusterSource['error']);
            }
            $relation['GalaxyClusterRelation']['galaxy_cluster_id'] = $clusterSource['SourceCluster']['id'];

            if (!empty($relation['GalaxyClusterRelation']['tags'])) {
                $tags = explode(',', $relation['GalaxyClusterRelation']['tags']);
                $tags = array_map('trim', $tags);
                $relation['GalaxyClusterRelation' ]['tags'] = $tags;
            } else {
                $relation['GalaxyClusterRelation' ]['tags'] = array();
            }

            if (empty($errors)) {
                $errors = $this->GalaxyClusterRelation->editRelation($this->Auth->user(), $relation);
            }

            if (empty($errors)) {
                $message = __('Relationship added.');
                $this->GalaxyClusterRelation->SourceCluster->touchTimestamp($clusterSource['SourceCluster']['id']);
                $this->GalaxyClusterRelation->SourceCluster->unpublish($clusterSource['SourceCluster']['id']);
            } else {
                $message = __('Relationship could not be added.');
            }
            if ($this->_isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'edit', $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'edit', false, $message, $this->response->type());
                }
                if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                    $errors[] = array(__('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to edit it.'));
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'index'));
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors), true));
                    $this->Flash->error($message);
                }
            }
        }
        $this->request->data = $existingRelation;
        $this->set('existingRelations', $this->GalaxyClusterRelation->getExistingRelationships());
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'edit');
        $this->render('add');
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $relation = $this->GalaxyClusterRelation->fetchRelations($this->Auth->user(), array('conditions' => array('GalaxyClusterRelation.id' => $id)));
            if (empty($relation)) {
                throw new NotFoundException(__('Relation not found.'));
            }
            $relation = $relation[0];
            $clusterSource = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], array('edit', 'publish'), $throwErrors=true, $full=false);
            $result = $this->GalaxyClusterRelation->delete($id, true);
            if ($result) {
                $this->GalaxyClusterRelation->SourceCluster->touchTimestamp($clusterSource['SourceCluster']['id']);
                $this->GalaxyClusterRelation->SourceCluster->unpublish($clusterSource['SourceCluster']['id']);
                $message = __('Galaxy cluster relationship successfuly deleted.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'delete', $id, $this->response->type());
                } else {
                    $this->Flash->success($message);
                    $this->redirect($this->referer());
                }
            } else {
                $message = __('Galaxy cluster relationship could not be deleted.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'delete', $id, $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect($this->referer());
                }
            }
        }
    }
}
