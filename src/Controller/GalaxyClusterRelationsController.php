<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Model\Entity\Distribution;
use Cake\Core\Configure;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Utility\Hash;

/**
 * @property GalaxyClusterRelation $GalaxyClusterRelation
 */
class GalaxyClusterRelationsController extends AppController
{
    use LocatorAwareTrait;

    public function initialize(): void
    {
        parent::initialize();
    }

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
        'recursive' => -1,
    ];

    public function index()
    {
        $filters = $this->request->getQueryParams();
        $GalaxyClusterRelationsTable = $this->fetchTable('GalaxyClusterRelations');
        $aclConditions = $GalaxyClusterRelationsTable->buildConditions($this->ACL->getUser());
        $contextConditions = [];
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        } else {
            $contextConditions = [];
            if ($filters['context'] == 'default') {
                $contextConditions = [
                    'GalaxyClusterRelations.default' => true
                ];
            } elseif ($filters['context'] == 'custom') {
                $contextConditions = [
                    'GalaxyClusterRelations.default' => false
                ];
            }
        }
        $this->set('passedArgsArray', ['context' => $filters['context'], 'searchall' => isset($filters['searchall']) ? $filters['searchall'] : '']);
        $this->set('context', $filters['context']);
        $searchConditions = [];
        if (empty($filters['searchall'])) {
            $filters['searchall'] = '';
        }
        if (strlen($filters['searchall']) > 0) {
            $searchall = '%' . strtolower($filters['searchall']) . '%';
            $searchConditions = [
                'OR' => [
                    'LOWER(GalaxyClusterRelations.referenced_galaxy_cluster_type) LIKE' => $searchall,
                    'LOWER(TargetCluster.value) LIKE' => $searchall,
                    'LOWER(TargetCluster.tag_name) LIKE' => $searchall,
                    'LOWER(SourceCluster.value) LIKE' => $searchall,
                    'LOWER(SourceCluster.tag_name) LIKE' => $searchall,
                ],
            ];
        }

        if ($this->ParamHandler->isRest()) {
            $conditions = [];
            if (!empty($contextConditions)) {
                $conditions['AND'][] = $contextConditions;
            }
            if (!empty($searchConditions)) {
                $conditions['AND'][] = $searchConditions;
            }
            if (!empty($aclConditions)) {
                $conditions['AND'][] = $aclConditions;
            }

            $relations = $GalaxyClusterRelationsTable->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => $conditions,
                    'contain' => ['SharingGroup', 'SourceCluster', 'TargetCluster', 'GalaxyClusterRelationTags' => ['Tags']]
                ]
            );
            $relations = $GalaxyClusterRelationsTable->removeNonAccessibleTargetCluster($this->ACL->getUser(), $relations);
            return $this->RestResponse->viewData($relations->toArray(), $this->response->getType());
        } else {
            $this->paginate['conditions']['AND'][] = $contextConditions;
            $this->paginate['conditions']['AND'][] = $searchConditions;
            $this->paginate['conditions']['AND'][] = $aclConditions;
            $this->paginate['contain'] = ['SharingGroup', 'SourceCluster' => ['Org', 'Orgc'], 'TargetCluster', 'GalaxyClusterRelationTag' => ['Tags']];
            $relations = $this->paginate();
            $relations = $GalaxyClusterRelationsTable->removeNonAccessibleTargetCluster($this->ACL->getUser(), $relations);
            $distributionLevels = Distribution::ALL;
            unset($distributionLevels[5]);
            $this->set('distributionLevels', $distributionLevels);
            $this->set('data', $relations);
        }
    }

    public function view($id)
    {
        if ($this->ParamHandler->isRest()) {
            $conditions = ['GalaxyClusterRelations.id' => $id];
            $GalaxyClusterRelationsTable = $this->fetchTable('GalaxyClusterRelations');
            $relation = $GalaxyClusterRelationsTable->fetchRelations(
                $this->ACL->getUser(),
                [
                    'conditions' => $conditions,
                    'contain' => ['SharingGroup', 'TargetCluster', 'GalaxyClusterRelationTags' => ['Tags']]
                ]
            )->toArray();
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
            return $this->RestResponse->viewData($relation, $this->response->getType());
        } else {
            throw new MethodNotAllowedException(__('This method can only be accessed via RestSearch.'));
        }
    }

    public function add()
    {
        $distributionLevels = Distribution::ALL;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $SharingGroupsTable = $this->fetchTable('SharingGroups');
        $sgs = $SharingGroupsTable->fetchAllAuthorised($this->ACL->getUser(), 'name', 1);

        if ($this->request->is('post')) {
            $errors = [];
            $data = $this->request->getData();
            if (empty($data['GalaxyClusterRelation'])) {
                $data = ['GalaxyClusterRelation' => $data];
            }
            $relation = $data;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $GalaxyClusterRelationsTable = $this->fetchTable('GalaxyClusterRelations');
            $clusterSource = $GalaxyClusterRelationsTable->SourceCluster->fetchIfAuthorized($this->ACL->getUser(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], ['edit', 'publish'], $throwErrors = false, $full = false);
            if (isset($clusterSource['authorized']) && !$clusterSource['authorized']) {
                $errors = [$clusterSource['error']];
            }

            if (!empty($relation['GalaxyClusterRelation']['tags'])) {
                $tags = explode(',', $relation['GalaxyClusterRelation']['tags']);
                $tags = array_map('trim', $tags);
                $relation['GalaxyClusterRelation']['tags'] = $tags;
            } else {
                $relation['GalaxyClusterRelation']['tags'] = [];
            }

            if (empty($errors)) {
                $errors = $GalaxyClusterRelationsTable->saveRelation($this->ACL->getUser(), $clusterSource, $relation);
            }

            if (empty($errors)) {
                $message = __('Relationship added.');
                $GalaxyClusterRelationsTable->SourceCluster->touchTimestamp($clusterSource['id']);
                $GalaxyClusterRelationsTable->SourceCluster->unpublish($clusterSource['id']);
            } else {
                $message = __('Relationship could not be added.');
            }
            if ($this->ParamHandler->isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'add', $message, $this->response->getType());
                } else {
                    $message .= sprintf('Reasons: %s', json_encode($errors));
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'add', $message, $this->response->getType());
                }
            } elseif ($this->request->is('ajax')) {
                $this->autoRender = false;
                if (empty($errors)) {
                    return new Response(['body' => json_encode(['saved' => true, 'success' => '']), 'status' => 200, 'type' => 'json']);
                } else {
                    $message .= sprintf('Reasons: %s', json_encode($errors));
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => $message]), 'status' => 200, 'type' => 'json']);
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    $this->redirect(['action' => 'index']);
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $GalaxyClusterRelationsTable->validationErrors)));
                    $this->Flash->error($message);
                }
            }
        }
        $this->set('existingRelations', $GalaxyClusterRelationsTable->getExistingRelationships());
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'add');
    }

    public function edit($id)
    {
        $conditions = ['conditions' => ['GalaxyClusterRelations.id' => $id], 'contain' => ['GalaxyClusterRelationTags' => 'Tags']];
        $GalaxyClusterRelationsTable = $this->fetchTable('GalaxyClusterRelations');
        $existingRelation = $GalaxyClusterRelationsTable->fetchRelations($this->ACL->getUser()->toArray(), $conditions)->toArray();
        if (empty($existingRelation)) {
            throw new NotFoundException(__('Invalid cluster relation'));
        }
        $existingRelation = $existingRelation[0];
        $id = $existingRelation['id'];
        if ($existingRelation['default']) {
            throw new MethodNotAllowedException(__('Default cluster relation cannot be edited'));
        }

        $existingRelation['tags'] = Hash::extract($existingRelation['Tag'], '{n}.Tag.name');
        $existingRelation['tags'] = implode(', ', $existingRelation['tags']);

        $distributionLevels = Distribution::ALL;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $SharingGroupsTable = $this->fetchTable('SharingGroups');
        $sgs = $SharingGroupsTable->fetchAllAuthorised($this->ACL->getUser(), 'name', 1);

        if ($this->request->is('post') || $this->request->is('put')) {
            $errors = [];
            $data = $this->request->getData();
            if (empty($data['GalaxyClusterRelation'])) {
                $data = ['GalaxyClusterRelation' => $data];
            }
            $relation = $data;
            $relation['GalaxyClusterRelation']['id'] = $id;
            if ($relation['GalaxyClusterRelation']['distribution'] != 4) {
                $relation['GalaxyClusterRelation']['sharing_group_id'] = null;
            }

            $clusterSource = $GalaxyClusterRelationsTable->SourceCluster->fetchIfAuthorized($this->ACL->getUser(), $relation['GalaxyClusterRelation']['galaxy_cluster_uuid'], ['edit', 'publish'], $throwErrors = false, $full = false);
            if (isset($clusterSource['authorized']) && !$clusterSource['authorized']) {
                $errors = [$clusterSource['error']];
            }
            $relation['GalaxyClusterRelation']['galaxy_cluster_id'] = $clusterSource['id'];

            if (!empty($relation['GalaxyClusterRelation']['tags'])) {
                $tags = explode(',', $relation['GalaxyClusterRelation']['tags']);
                $tags = array_map('trim', $tags);
                $relation['GalaxyClusterRelation']['tags'] = $tags;
            } else {
                $relation['GalaxyClusterRelation']['tags'] = [];
            }

            if (empty($errors)) {
                $errors = $GalaxyClusterRelationsTable->editRelation($this->ACL->getUser(), $relation);
            }

            if (empty($errors)) {
                $message = __('Relationship added.');
                $GalaxyClusterRelationsTable->SourceCluster->touchTimestamp($clusterSource['id']);
                $GalaxyClusterRelationsTable->SourceCluster->unpublish($clusterSource['id']);
            } else {
                $message = __('Relationship could not be added.');
            }
            if ($this->ParamHandler->isRest()) {
                if (empty($errors)) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'edit', $message, $this->response->getType());
                } else {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'edit', false, $message, $this->response->getType());
                }
                if (isset($relation['GalaxyClusterRelation']['distribution']) && $relation['GalaxyClusterRelation']['distribution'] == 4 && !$this->SharingGroup->checkIfAuthorised($this->ACL->getUser(), $relation['GalaxyClusterRelation']['sharing_group_id'])) {
                    $errors[] = [__('Galaxy Cluster Relation could not be saved: The user has to have access to the sharing group in order to be able to edit it.')];
                }
            } else {
                if (empty($errors)) {
                    $this->Flash->success($message);
                    $this->redirect(['action' => 'index']);
                } else {
                    $message .= __(' Reason: %s', json_encode(array_merge($errors, $GalaxyClusterRelationsTable->validationErrors), true));
                    $this->Flash->error($message);
                }
            }
        }
        $this->set('existingRelation', $existingRelation);
        $this->set('existingRelations', $GalaxyClusterRelationsTable->getExistingRelationships());
        $this->set('distributionLevels', $distributionLevels);
        $this->set('initialDistribution', $initialDistribution);
        $this->set('sharingGroups', $sgs);
        $this->set('action', 'edit');
        $this->render('add');
    }

    public function delete($id)
    {
        if ($this->request->is('post')) {
            $GalaxyClusterRelationsTable = $this->fetchTable('GalaxyClusterRelations');
            $relation = $GalaxyClusterRelationsTable->fetchRelations($this->ACL->getUser(), ['conditions' => ['GalaxyClusterRelations.id' => $id]])->toArray();
            if (empty($relation)) {
                throw new NotFoundException(__('Relation not found.'));
            }
            $relation = $relation[0];
            $clusterSource = $GalaxyClusterRelationsTable->SourceCluster->fetchIfAuthorized($this->ACL->getUser(), $relation['galaxy_cluster_uuid'], ['edit', 'publish'], $throwErrors = true, $full = false);

            $result = $GalaxyClusterRelationsTable->delete($relation, true);
            if ($result) {
                $GalaxyClusterRelationsTable->SourceCluster->touchTimestamp($clusterSource['id']);
                $GalaxyClusterRelationsTable->SourceCluster->unpublish($clusterSource['id']);
                $message = __('Galaxy cluster relationship successfuly deleted.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyClusterRelation', 'delete', $id, $this->response->getType());
                } else {
                    $this->Flash->success($message);
                    $this->redirect($this->referer());
                }
            } else {
                $message = __('Galaxy cluster relationship could not be deleted.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyClusterRelation', 'delete', $id, $message, $this->response->getType());
                } else {
                    $this->Flash->error($message);
                    $this->redirect($this->referer());
                }
            }
        }
    }
}
