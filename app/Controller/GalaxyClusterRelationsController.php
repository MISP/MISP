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
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
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

        $user = $this->Auth->user();
        $sourceContain = ['Org', 'Orgc'];
        $targetContain = [];
        if (!$this->_isRest()) {
            $sourceContain[] = 'Galaxy';
            $targetContain[] = 'Galaxy';
        }
        $this->CRUD->index([
            'conditions' => array(
                'AND' => array($contextConditions, $searchConditions, $aclConditions)
            ),
            'contain' => array('SharingGroup', 'SourceCluster' => $sourceContain, 'TargetCluster' => $targetContain, 'GalaxyClusterRelationTag' => array('Tag')),
            // Post-fetch ACL scrub — the same pruning the legacy index applied.
            'afterFind' => function (array $data) use ($user) {
                return $this->GalaxyClusterRelation->removeNonAccessibleTargetCluster($user, $data);
            },
            'limit' => $this->paginate['limit'],
            'maxLimit' => $this->paginate['maxLimit'],
        ]);
        if ($this->_isRest()) {
            return $this->restResponsePayload;
        }
        $this->loadModel('MispAttribute');
        $distributionLevels = $this->MispAttribute->distributionLevels;
        unset($distributionLevels[5]);
        $this->set('distributionLevels', $distributionLevels);
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

    /**
     * @param mixed $sourceId ID or UUID of the cluster the relationship starts from, fixing the source
     */
    public function add($sourceId = null)
    {
        $sourceCluster = null;
        if ($sourceId !== null) {
            $sourceCluster = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $sourceId, array('edit', 'publish'), true, false);
            $sourceCluster = $sourceCluster['GalaxyCluster'];
            $sourceCluster['Galaxy'] = $this->GalaxyClusterRelation->SourceCluster->Galaxy->find('first', array(
                'recursive' => -1,
                'conditions' => array('Galaxy.id' => $sourceCluster['galaxy_id']),
                'fields' => array('Galaxy.id', 'Galaxy.name', 'Galaxy.icon'),
            ))['Galaxy'] ?? [];
            $this->set('sourceCluster', $sourceCluster);
        }
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
            if ($sourceCluster !== null) {
                $this->request->data['GalaxyClusterRelation']['galaxy_cluster_uuid'] = $sourceCluster['uuid'];
            }
            $relation = $this->request->data;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusterSource = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], array('edit', 'publish'), $throwErrors=false, $full=false);
            if (isset($clusterSource['authorized']) && !$clusterSource['authorized']) {
                $errors = array($clusterSource['error']);
            }

            // Distribution 4 = sharing group: the user must have access to the SG to scope a
            // relation to it. editRelation() already enforces this via checkIfAuthorised; the
            // add path (saveRelation) did not, letting a galaxy editor assign a relation to a
            // sharing group they cannot access (scope-FK injection).
            if (empty($errors) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($this->Auth->user(), $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                $errors[] = __('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to use it.');
            }

            $relation['GalaxyClusterRelation']['tags'] = $this->__postedTagNames($relation['GalaxyClusterRelation']['tags'] ?? '');

            if (empty($errors)) {
                $errors = $this->GalaxyClusterRelation->saveRelation($this->Auth->user(), $clusterSource['GalaxyCluster'], $relation);
            }

            if (empty($errors)) {
                $message = __('Relationship added.');
                $this->GalaxyClusterRelation->SourceCluster->touchTimestamp($clusterSource['GalaxyCluster']['id']);
                $this->GalaxyClusterRelation->SourceCluster->unpublish($clusterSource['GalaxyCluster']['id']);
            } else {
                $message = __('Relationship could not be added.');
            }
            if ($this->_isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'add', $this->GalaxyClusterRelation->id, $this->response->type(), $message);
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
                    return $this->__redirectAfterSave();
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors)));
                    $this->Flash->error($message);
                }
            }
        } elseif ($sourceCluster !== null) {
            $this->request->data['GalaxyClusterRelation']['galaxy_cluster_uuid'] = $sourceCluster['uuid'];
        }
        $this->__setTagPicker(isset($relation) ? $relation['GalaxyClusterRelation']['tags'] : []);
        $this->set('existingRelations', $this->GalaxyClusterRelation->getExistingRelationships());
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'add');
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
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
            // Pin the source cluster to the stored relation's source. Both the authorisation
            // check below and editRelation() derive the saved galaxy_cluster_id from this uuid;
            // reading it from the request body let a user who could merely VIEW a relation
            // re-parent it onto a cluster they own (cross-cluster relation hijack), because edit
            // authorised the body-supplied source cluster, not the relation's actual one.
            // delete() already authorises against the stored source uuid - match it here.
            $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'] = $existingRelation['GalaxyClusterRelation']['galaxy_cluster_uuid'];
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusterSource = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], array('edit', 'publish'), $throwErrors=false, $full=false);
            if (isset($clusterSource['authorized']) && !$clusterSource['authorized']) {
                $errors = array($clusterSource['error']);
            } else {
                // Only present on success; reading it when the auth check failed (now reachable
                // since the source uuid is pinned to the stored, possibly un-owned, cluster)
                // would dereference a missing key.
                $relation['GalaxyClusterRelation']['galaxy_cluster_id'] = $clusterSource['GalaxyCluster']['id'];
            }

            $relation['GalaxyClusterRelation']['tags'] = $this->__postedTagNames($relation['GalaxyClusterRelation']['tags'] ?? '');

            if (empty($errors)) {
                $errors = $this->GalaxyClusterRelation->editRelation($this->Auth->user(), $relation);
            }

            if (empty($errors)) {
                $message = __('Relationship changed.');
                $this->GalaxyClusterRelation->SourceCluster->touchTimestamp($clusterSource['GalaxyCluster']['id']);
                $this->GalaxyClusterRelation->SourceCluster->unpublish($clusterSource['GalaxyCluster']['id']);
            } else {
                $message = __('Relationship could not be changed.');
            }
            if ($this->_isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'edit', $id, $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'edit', false, $message, $this->response->type());
                }
                if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($user, $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                    $errors[] = array(__('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to edit it.'));
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    return $this->__redirectAfterSave();
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $this->GalaxyClusterRelation->validationErrors), true));
                    $this->Flash->error($message);
                }
            }
        }
        $this->request->data = $existingRelation;
        $targetCluster = $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized($this->Auth->user(), $existingRelation['GalaxyClusterRelation']['referenced_galaxy_cluster_uuid'], 'view', false, false);
        if (isset($targetCluster['GalaxyCluster'])) {
            $this->set('targetCluster', $targetCluster['GalaxyCluster']);
        }
        $this->__setTagPicker(Hash::extract($existingRelation, 'GalaxyClusterRelationTag.{n}.Tag.name'));
        $this->set('existingRelations', $this->GalaxyClusterRelation->getExistingRelationships());
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'edit');
        if ($this->theme === 'Overmind') {
            $this->layout = false;
        }
        $this->render('add');
    }

    /**
     * Tag names from a posted `tags`: a comma separated string, or a list of
     * tag ids (the tag picker) and names.
     *
     * @param mixed $posted
     * @return string[]
     */
    private function __postedTagNames($posted)
    {
        if (!is_array($posted)) {
            return array_values(array_filter(array_map('trim', explode(',', (string)$posted)), 'strlen'));
        }
        $posted = array_filter(array_map('trim', $posted), 'strlen');
        $ids = array_filter($posted, 'ctype_digit');
        $names = array_values(array_diff($posted, $ids));
        if (!empty($ids)) {
            $this->loadModel('Tag');
            $names = array_merge($names, $this->Tag->find('column', [
                'conditions' => ['AND' => [$this->Tag->createConditions($this->Auth->user()), ['Tag.id' => array_values($ids)]]],
                'fields' => ['Tag.name'],
            ]));
        }
        return array_values(array_unique($names));
    }

    /**
     * @param string[] $selectedNames tags shown as already picked
     */
    private function __setTagPicker(array $selectedNames)
    {
        if ($this->theme !== 'Overmind') {
            return;
        }
        $this->loadModel('Tag');
        $user = $this->Auth->user();
        $selected = [];
        if (!empty($selectedNames)) {
            $rows = $this->Tag->find('all', [
                'conditions' => ['AND' => [$this->Tag->createConditions($user), ['Tag.name' => $selectedNames]]],
                'fields' => ['Tag.id', 'Tag.name', 'Tag.colour'],
                'recursive' => -1,
            ]);
            foreach ($rows as $row) {
                $selected[] = ['id' => (int)$row['Tag']['id'], 'name' => $row['Tag']['name'], 'colour' => $row['Tag']['colour']];
            }
        }
        $this->set('pickerAllTags', $this->Tag->getAllTagsForPicker($user));
        $this->set('pickerCustomTags', $this->Tag->getCustomTagsForPicker($user));
        $this->set('currentTags', $selected);
    }

    /**
     * Back to the cluster page the form was opened from, else the index.
     */
    private function __redirectAfterSave()
    {
        $path = (string)parse_url((string)env('HTTP_REFERER'), PHP_URL_PATH);
        $base = (string)$this->request->base;
        if ($base !== '' && strpos($path, $base . '/') === 0) {
            $path = substr($path, strlen($base));
        }
        if (preg_match('#^/galaxy_?clusters/view/([\w-]+)$#i', $path, $matches)) {
            return $this->redirect(array('controller' => 'galaxy_clusters', 'action' => 'view', $matches[1]));
        }
        return $this->redirect(array('action' => 'index'));
    }

    public function delete($id)
    {
        // Overmind non-POST request: render the themed BS5 confirmation fragment
        // (injected into #mainModalBody by openModal()) instead of the legacy
        // /genericTemplates/delete confirm.
        if ($this->theme === 'Overmind' && !$this->_isRest()
            && !$this->request->is('post') && !$this->request->is('delete')
        ) {
            $relation = $this->GalaxyClusterRelation->fetchRelations($this->Auth->user(), array(
                'conditions' => array('GalaxyClusterRelation.id' => $id),
                'contain' => array('SourceCluster', 'TargetCluster'),
            ));
            if (empty($relation)) {
                throw new NotFoundException(__('Relation not found.'));
            }
            // NB: do NOT seed request->data[...]['id'] here — FormHelper would
            // switch the confirm form to _method=PUT, which CRUD->delete ignores
            // (it only accepts POST/DELETE). The id travels in the URL.
            $this->set('relation', $relation[0]);
            $this->layout = false;
            return $this->render('ajax/galaxyClusterRelationDeleteConfirmationForm');
        }
        $user = $this->Auth->user();
        $this->CRUD->delete($id, [
            // ACL scoping — mirrors the fetchRelations() the bespoke delete used.
            'conditions' => $this->GalaxyClusterRelation->buildConditions($user),
            'contain' => ['SourceCluster'],
            'beforeDelete' => function (array $relation) use ($user) {
                // Throws if the user may not edit/publish the source cluster.
                $this->GalaxyClusterRelation->SourceCluster->fetchIfAuthorized(
                    $user,
                    $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'],
                    array('edit', 'publish'),
                    $throwErrors = true,
                    $full = false
                );
                return $relation;
            },
            'afterDelete' => function (array $relation) {
                $clusterId = $relation['GalaxyClusterRelation']['galaxy_cluster_id'];
                $this->GalaxyClusterRelation->SourceCluster->touchTimestamp($clusterId);
                $this->GalaxyClusterRelation->SourceCluster->unpublish($clusterId);
            },
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
