<?php

namespace App\Controller;

use App\Lib\Tools\ClusterRelationsTreeTool;
use App\Lib\Tools\ColourGradientTool;
use App\Model\Entity\Distribution;
use Cake\Core\Configure;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Routing\Router;
use Cake\Utility\Hash;
use Cake\Validation\Validation;

class GalaxyClustersController extends AppController
{
    use LocatorAwareTrait;

    protected $conditions = [];
    protected $contain =  [
        'Tag' => [
            'fields' => ['Tag.id'],
            /*
            'EventTag' => array(
                'fields' => array('EventTag.event_id')
            ),
            'AttributeTag' => array(
                'fields' => array('AttributeTag.event_id', 'AttributeTag.attribute_id')
            )
            */
        ],
        'GalaxyElement' => [
            'conditions' => ['GalaxyElement.key' => 'synonyms'],
            'fields' => ['value']
        ],
    ];
    public $paginate = [
        'limit' => 60,
        'order' => [
            'GalaxyClusters.version' => 'DESC',
            'GalaxyClusters.value' => 'ASC'
        ],
    ];

    public function initialize(): void
    {
        $this->loadComponent('Toolbox');
        parent::initialize();
    }

    public function index($galaxyId)
    {
        $galaxyId = $this->Toolbox->findIdByUuid($this->GalaxyClusters->Galaxy, $galaxyId);
        $filterData = [
            'request' => $this->request,
            'named_params' => $this->request->getParam('named'),
            'paramArray' => ['context', 'searchall'],
            'ordered_url_params' => [],
            'additional_delimiters' => PHP_EOL
        ];
        $exception = false;
        $filters = $this->harvestParameters($filterData, $exception);
        $aclConditions = $this->GalaxyClusters->buildConditions($this->ACL->getUser());
        $contextConditions = [];
        if (empty($filters['context'])) {
            $filters['context'] = 'all';
        } else {
            $contextConditions = ['GalaxyClusters.deleted' => false];
        }

        if ($filters['context'] == 'default') {
            $contextConditions['GalaxyClusters.default'] = true;
        } elseif ($filters['context'] == 'custom') {
            $contextConditions['GalaxyClusters.default'] = false;
        } elseif ($filters['context'] == 'org') {
            $contextConditions['GalaxyClusters.org_id'] = $this->Auth->user('org_id');
        } elseif ($filters['context'] == 'deleted') {
            $contextConditions['GalaxyClusters.deleted'] = true;
        }

        $this->set('passedArgs', json_encode(['context' => $filters['context'], 'searchall' => isset($filters['searchall']) ? $filters['searchall'] : '']));
        $this->set('context', $filters['context']);
        $searchConditions = [];
        if (empty($filters['searchall'])) {
            $filters['searchall'] = '';
        }
        if (strlen($filters['searchall']) > 0) {
            $searchall = '%' . strtolower($filters['searchall']) . '%';
            $synonym_hits = $this->GalaxyClusters->GalaxyElement->find(
                'list',
                [
                    'recursive' => -1,
                    'conditions' => [
                        'LOWER(GalaxyElement.value) LIKE' => $searchall,
                        'GalaxyElement.key' => 'synonyms'
                    ],
                    'fields' => [
                        'GalaxyElement.galaxy_cluster_id'
                    ]
                ]
            );
            $searchConditions = [
                'OR' => [
                    'LOWER(GalaxyClusters.value) LIKE' => $searchall,
                    'LOWER(GalaxyClusters.description) LIKE' => $searchall,
                    'GalaxyClusters.uuid' => $filters['searchall'],
                    'GalaxyClusters.id' => array_values($synonym_hits),
                ],
            ];
        }
        $searchConditions['GalaxyClusters.galaxy_id'] = $galaxyId;

        if ($this->ParamHandler->isRest()) {
            $clusters = $this->GalaxyClusters->find(
                'all',
                [
                    'conditions' => [
                        'AND' => [$contextConditions, $searchConditions, $aclConditions]
                    ],
                ]
            )->toArray();
            return $this->RestResponse->viewData($clusters, $this->response->getType());
        }

        $this->conditions['AND'][] = $contextConditions;
        $this->conditions['AND'][] = $searchConditions;
        $this->conditions['AND'][] = $aclConditions;
        $this->contain = array_merge($this->contain, ['Org', 'Orgc', 'SharingGroup', 'GalaxyClusterRelation', 'TargetingClusterRelation']);

        $query = $this->GalaxyClusters->find(
            'all',
            [
                'conditions' => $this->conditions,
                'contain' => $this->contain
            ]
        );
        $clusters = $this->paginate($query);

        $this->GalaxyClusters->attachExtendByInfo($this->ACL->getUser()->toArray(), $clusters);

        $tagIds = [];
        foreach ($clusters as $k => $cluster) {
            $clusters[$k] = $this->GalaxyClusters->attachExtendFromInfo($this->ACL->getUser()->toArray(), $clusters[$k]);
            $clusters[$k]['GalaxyCluster']['relation_counts'] = [
                'out' => count($clusters[$k]['GalaxyClusterRelation']),
                'in' => count($clusters[$k]['TargetingClusterRelation']),
            ];

            if (isset($cluster['Tag']['id'])) {
                $tagIds[] = $cluster['Tag']['id'];
                $clusters[$k]['GalaxyCluster']['tag_id'] = $cluster['Tag']['id'];
            }
            $clusters[$k]['GalaxyCluster']['synonyms'] = [];
            foreach ($cluster['GalaxyElement'] as $element) {
                $clusters[$k]['GalaxyCluster']['synonyms'][] = $element['value'];
            }
            $clusters[$k]['GalaxyCluster']['event_count'] = 0; // real number is assigned later
        }

        $eventCountsForTags = $this->GalaxyClusters->Tag->EventTag->countForTags($tagIds, $this->ACL->getUser());

        $SightingsTable = $this->fetchTable('Sightings');

        $csvForTags = $SightingsTable->tagsSparkline($tagIds, $this->ACL->getUser()->toArray(), '0');
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
        $customClusterCount = $this->GalaxyClusters->fetchGalaxyClusters(
            $this->ACL->getUser()->toArray(),
            [
                'count' => true,
                'conditions' => [
                    'AND' => [$searchConditions, $aclConditions],
                    'GalaxyClusters.default' => 0,
                ]
            ]
        );

        $EventsTable = $this->fetchTable('Events');

        $distributionLevels = $EventsTable->shortDist;
        $this->set('distributionLevels', $distributionLevels);
        $this->set('list', $clusters);
        $this->set('galaxy_id', $galaxyId);
        $this->set('custom_cluster_count', $customClusterCount);

        if ($this->request->is('ajax')) {
            $this->layout = false;
            $this->render('ajax/index');
        }
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function view($id)
    {
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'view', $throwErrors = true, $full = true);
        $tag = $this->GalaxyClusters->Tag->find(
            'all',
            [
                'conditions' => [
                    'LOWER(name)' => strtolower($cluster['tag_name']),
                ],
                'fields' => ['id'],
                'recursive' => -1,
                'contain' => ['EventTag' => ['fields' => ['event_id']]]
            ]
        )->first();
        if (!empty($tag)) {
            $cluster['GalaxyCluster']['tag_count'] = $this->GalaxyClusters->Tag->EventTag->countForTag($tag['Tag']['id'], $this->ACL->getUser());
            $cluster['GalaxyCluster']['tag_id'] = $tag['Tag']['id'];
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($cluster, $this->response->getType());
        }

        $clusters = [$cluster];
        $this->GalaxyClusters->attachExtendByInfo($this->ACL->getUser()->toArray(), $clusters);
        $cluster = $clusters[0];
        $cluster = $this->GalaxyClusters->attachExtendFromInfo($this->ACL->getUser()->toArray(), $cluster);
        $this->set('id', $cluster['GalaxyCluster']['id']);
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
        $distributionLevels = Distribution::ALL;
        $this->set('distributionLevels', $distributionLevels);
        if (!$cluster['GalaxyCluster']['default'] && !$cluster['GalaxyCluster']['published'] && $cluster['GalaxyCluster']['orgc_id'] == $this->ACL->getUser()['org_id']) {
            $this->Flash->warning(__('This cluster is not published. Users will not be able to use it'));
        }
        $this->set('title_for_layout', __('Galaxy cluster %s', $cluster['GalaxyCluster']['value']));
    }

    /**
     * @param  mixed $galaxyId ID of the galaxy to which the cluster will be added
     */
    public function add($galaxyId)
    {
        if (Validation::uuid($galaxyId)) {
            $temp = $this->GalaxyClusters->Galaxy->find(
                'all',
                [
                    'recursive' => -1,
                    'fields' => ['Galaxy.id', 'Galaxy.uuid'],
                    'conditions' => ['Galaxy.uuid' => $galaxyId]
                ]
            )->first();
            if ($temp === null) {
                throw new NotFoundException(__('Invalid galaxy'));
            }
            $galaxyId = $temp['Galaxy']['id'];
        } elseif (!is_numeric($galaxyId)) {
            throw new NotFoundException(__('Invalid galaxy'));
        }
        $distributionLevels = Distribution::ALL;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $SharingGroupsTable = $this->fetchTable('SharingGroups');
        $sgs = $SharingGroupsTable->fetchAllAuthorised($this->ACL->getUser(), 'name', 1);

        if (isset($this->request->getParam('named')['forkUuid'])) {
            $forkUuid = $this->request->getParam('named')['forkUuid'];
            $forkedCluster = $this->GalaxyClusters->fetchGalaxyClusters(
                $this->ACL->getUser()->toArray(),
                [
                    'conditions' => ['GalaxyClusters.uuid' => $forkUuid],
                ],
                true
            );
            if (!empty($forkedCluster)) {
                $forkedCluster = $forkedCluster[0];
                $forkedClusterMeta = $forkedCluster['GalaxyCluster'];
                if (empty($this->request->getData())) {
                    $data = $forkedCluster;
                    unset($data['GalaxyCluster']['id']);
                    unset($data['GalaxyCluster']['uuid']);
                    foreach ($forkedCluster['GalaxyCluster']['GalaxyElement'] as $k => $element) {
                        unset($forkedCluster['GalaxyCluster']['GalaxyElement'][$k]['id']);
                        unset($forkedCluster['GalaxyCluster']['GalaxyElement'][$k]['galaxy_cluster_id']);
                    }
                    $data['GalaxyCluster']['extends_uuid'] = $forkedCluster['GalaxyCluster']['uuid'];
                    $data['GalaxyCluster']['extends_version'] = $forkedCluster['GalaxyCluster']['version'];
                    $data['GalaxyCluster']['elements'] = json_encode($forkedCluster['GalaxyCluster']['GalaxyElement']);
                    $data['GalaxyCluster']['elementsDict'] = $forkedCluster['GalaxyCluster']['GalaxyElement'];
                    $data['GalaxyCluster']['authors'] = json_encode($forkedCluster['GalaxyCluster']['authors']);
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
            $cluster = $this->request->getData();
            if (!isset($cluster['GalaxyCluster'])) {
                $cluster = ['GalaxyCluster' => $cluster];
            }
            $cluster['GalaxyCluster']['galaxy_id'] = $galaxyId;
            $cluster['GalaxyCluster']['published'] = false;
            $errors = [];
            if (empty($cluster['GalaxyCluster']['elements'])) {
                if (empty($cluster['GalaxyCluster']['GalaxyElement'])) {
                    $cluster['GalaxyCluster']['GalaxyElement'] = [];
                }
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['elements'], true);
                if (is_null($decoded)) {
                    $this->GalaxyClusters->validationErrors['values'][] = __('Invalid JSON');
                    $errors[] = sprintf(__('Invalid JSON'));
                }
                $cluster['GalaxyCluster']['GalaxyElement'] = $decoded;
            }
            if (!empty($cluster['GalaxyCluster']['extends_uuid'])) {
                $extendId = $this->Toolbox->findIdByUuid($this->GalaxyCluster, $cluster['GalaxyCluster']['extends_uuid']);
                $forkedCluster = $this->GalaxyClusters->fetchGalaxyClusters(
                    $this->ACL->getUser()->toArray(),
                    ['conditions' => ['GalaxyClusters.id' => $extendId]]
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
            try {
                [$errors, $galaxyClusterEntity] = $this->GalaxyClusters->saveCluster($this->ACL->getUser()->toArray(), $cluster);
            } catch (\Exception $e) {
                $errors[] = $e->getMessage();
            }
            if (!empty($errors)) {
                $message = implode(', ', $errors);
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'add', '', $message, $this->response->getType());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                $message = __('Galaxy cluster saved');
                if ($this->request->is('ajax')) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'add', $galaxyClusterEntity->id, $this->response->getType());
                } else if ($this->ParamHandler->isRest()) {
                    $saved_cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $galaxyClusterEntity->id, 'view', $throwErrors = true, $full = true);
                    return $this->RestResponse->viewData($saved_cluster);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'galaxy_clusters', 'action' => 'view', $galaxyClusterEntity->id]);
                }
            }
        }
        $this->set('galaxy', ['Galaxy' => ['id' => $galaxyId]]);
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
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'edit', $throwErrors = true, $full = true);
        $data = ['GalaxyCluster' => $cluster, 'GalaxyElement' => $cluster['GalaxyElement'] ?? []];

        $distributionLevels = Distribution::ALL;
        unset($distributionLevels[5]);
        $initialDistribution = 3;
        $configuredDistribution = Configure::check('MISP.default_attribute_distribution');
        if ($configuredDistribution != null && $configuredDistribution != 'event') {
            $initialDistribution = $configuredDistribution;
        }
        $SharingGroupsTable = $this->fetchTable('SharingGroups');
        $sgs = $SharingGroupsTable->fetchAllAuthorised($this->ACL->getUser(), 'name', 1);

        if (!empty($cluster['extends_uuid'])) {
            $forkedCluster = $this->GalaxyClusters->fetchGalaxyClusters(
                $this->ACL->getUser()->toArray(),
                [
                    'conditions' => ['uuid' => $cluster['extends_uuid']],
                ],
                false
            );
        } else {
            $forkedCluster = [];
        }

        if (!empty($forkedCluster)) {
            $forkedCluster = $forkedCluster[0];
            $this->set('forkUuid', $cluster['extends_uuid']);
            $forkedClusterMeta = $forkedCluster['GalaxyCluster'];
            $this->set('forkedCluster', $forkedCluster);
            $this->set('forkedClusterMeta', $forkedClusterMeta);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $cluster = $this->request->getData();
            if (isset($cluster['default'])) {
                throw new MethodNotAllowedException('Default galaxy cluster cannot be edited');
            }
            if (!isset($cluster['GalaxyCluster'])) {
                $cluster = ['GalaxyCluster' => $cluster];
            }
            $errors = [];
            if (!isset($cluster['GalaxyCluster']['uuid'])) {
                $cluster['GalaxyCluster']['uuid'] = $data['GalaxyCluster']['uuid']; // freeze the uuid
            }
            if (!isset($cluster['GalaxyCluster']['id'])) {
                $cluster['GalaxyCluster']['id'] = $id;
            }

            if (empty($cluster['GalaxyCluster']['elements'])) {
                if (empty($cluster['GalaxyCluster']['GalaxyElement'])) {
                    $cluster['GalaxyCluster']['GalaxyElement'] = [];
                }
            } else {
                $decoded = json_decode($cluster['GalaxyCluster']['elements'], true);
                if (is_null($decoded)) {
                    $this->GalaxyClusters->validationErrors['values'][] = __('Invalid JSON');
                    $errors[] = sprintf(__('Invalid JSON'));
                }
                $cluster['GalaxyCluster']['GalaxyElement'] = $decoded;
            }

            if (empty($cluster['GalaxyCluster']['authors'])) {
                $cluster['GalaxyCluster']['authors'] = [];
            } else if (is_array($cluster['GalaxyCluster']['authors'])) {
                // This is as intended, move on
            } else {
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
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'edit', $cluster['GalaxyCluster']['id'], $message, $this->response->getType());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                try {
                    [$errors, $clusterEntity] = $this->GalaxyClusters->editCluster($this->ACL->getUser()->toArray(), $cluster);
                } catch (\Exception $e) {
                    $errors[] = $e->getMessage();
                }
                if (!empty($errors)) {
                    $message = implode(', ', $errors);
                    if ($this->ParamHandler->isRest()) {
                        return $this->RestResponse->saveFailResponse('GalaxyCluster', 'edit', $cluster['GalaxyCluster']['id'], $message, $this->response->getType());
                    } else {
                        $this->Flash->error($message);
                    }
                } else {
                    $message = __('Galaxy cluster saved');
                    if ($this->request->is('ajax')) {
                        return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'edit', $cluster['GalaxyCluster']['id'], $this->response->getType());
                    } else if ($this->ParamHandler->isRest()) {
                        $saved_cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'view', $throwErrors = true, $full = true);
                        return $this->RestResponse->viewData($saved_cluster);
                    } else {
                        $this->Flash->success($message);
                        $this->redirect(['controller' => 'galaxy_clusters', 'action' => 'view', $clusterEntity->id]);
                    }
                }
            }
        } else {
            $data['GalaxyCluster']['elements'] = json_encode($data['GalaxyElement']);
            $data['GalaxyCluster']['elementsDict'] = $data['GalaxyElement'];
            $data['GalaxyCluster']['authors'] = !empty($data['GalaxyCluster']['authors']) ? json_encode($data['GalaxyCluster']['authors']) : '';
        }
        $fieldDesc = [
            'authors' => __('Valid JSON array or comma separated'),
            'elements' => __('Valid JSON array composed from Object of the form {key: keyname, value: actualValue}'),
            'distribution' => Hash::extract(Distribution::DESCRIPTIONS, '{n}.formdesc'),
        ];
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
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'publish', $throwErrors = true, $full = false);
        if ($cluster['published']) {
            throw new MethodNotAllowedException(__('You can\'t publish a galaxy cluster that is already published'));
        }
        if ($cluster['default']) {
            throw new MethodNotAllowedException(__('Default galaxy cluster cannot be published'));
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $success = $this->GalaxyClusters->publishRouter($this->ACL->getUser()->toArray(), $cluster, $passAlong = null);
            if (Configure::read('BackgroundJobs.enabled')) {
                $message = __('Publish job queued. Job ID: %s', $success);
                $this->Flash->success($message);
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->viewData(['message' => $message], $this->response->getType());
                }
            } else {
                $success = $this->GalaxyClusters->publish($cluster);
                if (!$success) {
                    $message = __('Could not publish galaxy cluster');
                    if ($this->ParamHandler->isRest()) {
                        return $this->RestResponse->saveFailResponse('GalaxyCluster', 'publish', $cluster['id'], $message, $this->response->getType());
                    } else {
                        $this->Flash->error($message);
                    }
                } else {
                    $message = __('Galaxy cluster published');
                    if ($this->ParamHandler->isRest()) {
                        return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'publish', $cluster['id'], $this->response->getType());
                    } else {
                        $this->Flash->success($message);
                    }
                }
            }
            $this->redirect(['controller' => 'galaxy_clusters', 'action' => 'view', $cluster['id']]);
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
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'publish', $throwErrors = true, $full = false);
        if (!$cluster['published']) {
            throw new MethodNotAllowedException(__('You can\'t unpublish a galaxy cluster that is not published'));
        }
        if ($cluster['default']) {
            throw new MethodNotAllowedException(__('Default galaxy cluster cannot be unpublished'));
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $success = $this->GalaxyClusters->unpublish($cluster);
            if (!$success) {
                $message = __('Could not unpublish galaxy cluster');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'unpublish', $cluster['id'], $message, $this->response->getType());
                } else {
                    $this->Flash->error($message);
                }
            } else {
                $message = __('Galaxy cluster unpublished');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'unpublish', $cluster['id'], $this->response->getType());
                } else {
                    $this->Flash->success($message);
                }
            }
            $this->redirect(['controller' => 'galaxy_clusters', 'action' => 'view', $cluster['id']]);
        } else {
            $this->set('cluster', $cluster);
            $this->set('type', 'unpublish');
            $this->render('ajax/publishConfirmationForm');
        }
    }

    public function detach($target_id, $target_type, $tag_id)
    {
        if ($this->request->is('ajax') && $this->request->is('get')) {
            $this->set('url', Router::url());
            return $this->render('/Elements/emptyForm', false);
        }

        $this->request->allowMethod(['post']);

        try {
            $this->GalaxyClusters->Galaxy->detachClusterByTagId($this->ACL->getUser()->toArray(), $target_id, $target_type, $tag_id);
        } catch (NotFoundException $e) {
            if (!$this->request->is('ajax')) {
                $this->Flash->error($e->getMessage());
            } else {
                throw $e;
            }
        }

        $message = __('Galaxy successfully detached.');

        if ($this->request->is('ajax')) {
            return $this->RestResponse->viewData(['saved' => true, 'check_publish' => true, 'success' => $message], 'json');
        }

        $this->Flash->success($message);
        $this->redirect($this->referer());
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function delete($id, $hard = false)
    {
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'delete', $throwErrors = true, $full = false);
        if ($this->request->is('post')) {
            if (!empty($this->request->getData()['hard'])) {
                $hard = true;
            }
            $result = $this->GalaxyClusters->deleteCluster($cluster['id'], $hard = $hard);
            $galaxyId = $cluster['galaxy_id'];
            if ($result) {
                $message = __(
                    'Galaxy cluster successfuly %s deleted%s.',
                    $hard ? __('hard') : __('soft'),
                    $hard ? __(' and added to the block list') : ''
                );
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'delete', $cluster['id'], $this->response->getType(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'galaxies', 'action' => 'view', $galaxyId]);
                }
            } else {
                $message = __('Galaxy cluster could not be %s deleted.', $hard ? __('hard') : __('soft'));
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'delete', $cluster['id'], $message, $this->response->getType(), $message);
                } else {
                    $this->Flash->error($message);
                    $this->redirect(['controller' => 'galaxies', 'action' => 'view', $galaxyId]);
                }
            }
        } else {
            if ($this->request->is('ajax')) {
                $this->set('id', $cluster['id']);
                $this->set('cluster', $cluster);
                $this->render('ajax/galaxy_cluster_delete_confirmation');
            } else {
                throw new MethodNotAllowedException(__('This function can only be reached via AJAX.'));
            }
        }
    }

    public function restore($id)
    {
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'delete', $throwErrors = true, $full = false);
        if ($this->request->is('post')) {
            $result = $this->GalaxyClusters->restoreCluster($cluster['id']);
            $galaxyId = $cluster['galaxy_id'];
            if ($result) {
                $message = __('Galaxy cluster successfuly restored.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('GalaxyCluster', 'restore', $cluster['id'], $this->response->getType());
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'galaxies', 'action' => 'view', $galaxyId]);
                }
            } else {
                $message = __('Galaxy cluster could not be %s restored.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('GalaxyCluster', 'restore', $cluster['id'], $message, $this->response->getType());
                } else {
                    $this->Flash->error($message);
                    $this->redirect(['controller' => 'galaxies', 'action' => 'view', $galaxyId]);
                }
            }
        } else {
            throw new MethodNotAllowedException(__('This function can only be reached via POST.'));
        }
    }

    public function viewCyCatRelations($id)
    {
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'view', true, false);
        $CyCatRelations = $this->GalaxyClusters->getCyCatRelations($cluster);
        $this->set('cluster', $cluster);
        $this->set('CyCatRelations', $CyCatRelations);
        $this->render('cluster_cycatrelations');
    }

    public function viewGalaxyMatrix($id)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be reached via AJAX.');
        }

        $cluster = $this->GalaxyClusters->fetchGalaxyClusters(
            $this->ACL->getUser()->toArray(),
            [
                'conditions' => ['id' => $id]
            ],
            $full = false
        );
        if (empty($cluster)) {
            throw new MethodNotAllowedException("Invalid Galaxy Cluster.");
        }
        $cluster = $cluster[0];
        $EventsTable = $this->fetchTable('Events');
        $mitreAttackGalaxyId = $this->GalaxyClusters->Galaxy->getMitreAttackGalaxyId();
        if ($mitreAttackGalaxyId == 0) { // Mitre Att&ck galaxy not found
            return new Response(['body' => '', 'status' => 200, 'type' => 'text']);
        }
        $attackPatternTagNames = $this->GalaxyClusters->find(
            'list',
            [
                'conditions' => ['galaxy_id' => $mitreAttackGalaxyId],
                'fields' => ['tag_name']
            ]
        );

        $cluster = $cluster['GalaxyCluster'];
        $tag_name = $cluster['tag_name'];

        // fetch all event ids having the requested cluster
        $eventIds = $EventsTable->EventTag->find(
            'list',
            [
                'contain' => ['Tag'],
                'conditions' => [
                    'Tag.name' => $tag_name
                ],
                'fields' => ['event_id'],
                'recursive' => -1
            ]
        );

        // fetch all attribute ids having the requested cluster
        $attributes = $EventsTable->Attribute->AttributeTag->find(
            'all',
            [
                'contain' => ['Tag'],
                'conditions' => [
                    'Tag.name' => $tag_name
                ],
                'fields' => ['attribute_id', 'event_id'],
                'recursive' => -1
            ]
        );
        $attributeIds = [];
        $additional_event_ids = [];
        foreach ($attributes as $attribute) {
            $attributeIds[] = $attribute['AttributeTag']['attribute_id'];
            $additional_event_ids[$attribute['AttributeTag']['event_id']] = $attribute['AttributeTag']['event_id'];
        }
        $additional_event_ids = array_keys($additional_event_ids);
        $eventIds = array_merge($eventIds, $additional_event_ids);
        unset($attributes);
        unset($additional_event_ids);

        // fetch all related tags belonging to attack pattern
        $eventTags = $EventsTable->EventTag->find(
            'all',
            [
                'contain' => ['Tag'],
                'conditions' => [
                    'event_id' => $eventIds,
                    'Tag.name' => $attackPatternTagNames
                ],
                'fields' => ['Tag.name, COUNT(DISTINCT event_id) as tag_count'],
                'recursive' => -1,
                'group' => ['Tag.name', 'Tag.id']
            ]
        );

        // fetch all related tags belonging to attack pattern or belonging to an event having this cluster
        $attributeTags = $EventsTable->Attribute->AttributeTag->find(
            'all',
            [
                'contain' => ['Tag'],
                'conditions' => [
                    'OR' => [
                        'event_id' => $eventIds,
                        'attribute_id' => $attributeIds
                    ],
                    'Tag.name' => $attackPatternTagNames
                ],
                'fields' => ['Tag.name, COUNT(DISTINCT event_id) as tag_count'],
                'recursive' => -1,
                'group' => ['Tag.name', 'Tag.id']
            ]
        );

        $scores = [];
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
        $matrixData = $this->GalaxyClusters->Galaxy->getMatrix($mitreAttackGalaxyId, $scores);
        $tabs = $matrixData['tabs'];
        $matrixTags = $matrixData['matrixTags'];
        $killChainOrders = $matrixData['killChain'];
        $instanceUUID = $matrixData['instance-uuid'];

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
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'edit', $throwErrors = true, $full = true);
        if ($cluster['GalaxyCluster']['default']) {
            throw new MethodNotAllowedException(__('Default galaxy cluster cannot be updated'));
        }
        if (empty($cluster['GalaxyCluster']['extends_uuid'])) {
            throw new NotFoundException(__('Galaxy cluster is not a fork'));
        }
        $conditions = ['conditions' => ['GalaxyClusters.uuid' => $cluster['GalaxyCluster']['extends_uuid']]];
        $parentCluster = $this->GalaxyClusters->fetchGalaxyClusters($this->ACL->getUser()->toArray(), $conditions, true);
        if (empty($parentCluster)) {
            throw new NotFoundException('Invalid parent galaxy cluster');
        }
        $parentCluster = $parentCluster[0];
        $forkVersion = $cluster['GalaxyCluster']['extends_version'];
        $parentVersion = $parentCluster['GalaxyCluster']['version'];
        if ($this->request->is('post') || $this->request->is('put')) {
            $elements = [];
            if (!empty($this->request->getData()['GalaxyCluster'])) {
                foreach ($this->request->getData()['GalaxyCluster'] as $k => $jElement) {
                    $element = json_decode($jElement, true);
                    if (!is_null($element) && $element != 0) {
                        $elements[] = [
                            'key' => $element['key'],
                            'value' => $element['value'],
                        ];
                    }
                }
            }
            $cluster['GalaxyCluster']['GalaxyElement'] = $elements;
            $cluster['GalaxyCluster']['extends_version'] = $parentVersion;
            $cluster['GalaxyCluster']['published'] = false;
            $errors = $this->GalaxyClusters->editCluster($this->ACL->getUser()->toArray(), $cluster, $fieldList = ['extends_version', 'published'], $deleteOldElements = false);
            if (!empty($errors)) {
                $flashErrorMessage = implode(', ', $errors);
                $this->Flash->error($flashErrorMessage);
            } else {
                $this->Flash->success(__('Cluster updated to the newer version'));
                $this->redirect(['controller' => 'galaxy_clusters', 'action' => 'view', $id]);
            }
        }
        $missingElements = [];
        foreach ($parentCluster['GalaxyCluster']['GalaxyElement'] as $k => $parentElement) {
            $found = false;
            foreach ($cluster['GalaxyCluster']['GalaxyElement'] as $k => $clusterElement) {
                if (
                    $parentElement['key'] == $clusterElement['key'] &&
                    $parentElement['value'] == $clusterElement['value']
                ) {
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
    public function viewRelations($id, $includeInbound = 1)
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException('This function can only be reached via AJAX.');
        }
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'view', true, true);
        $existingRelations = $this->GalaxyClusters->GalaxyClusterRelation->getExistingRelationships();
        $cluster = $this->GalaxyClusters->attachClusterToRelations($this->ACL->getUser()->toArray(), $cluster, $includeInbound);

        $grapher = new ClusterRelationsTreeTool();
        $grapher->construct($this->ACL->getUser()->toArray(), $this->GalaxyCluster);
        $tree = $grapher->getTree($cluster);

        $this->set('existingRelations', $existingRelations);
        $this->set('cluster', $cluster);
        $relations = $cluster['GalaxyCluster']['GalaxyClusterRelation'];
        if ($includeInbound && !empty($cluster['GalaxyCluster']['TargetingClusterRelation'])) {
            foreach ($cluster['GalaxyCluster']['TargetingClusterRelation'] as $targetingCluster) {
                $targetingCluster['isInbound'] = true;
                $relations[] = $targetingCluster;
            }
        }
        $this->set('passedArgs', json_encode([]));
        $this->set('relations', $relations);
        $this->set('tree', $tree);
        $this->set('includeInbound', $includeInbound);
        $distributionLevels = Distribution::ALL;
        unset($distributionLevels[4]);
        unset($distributionLevels[5]);
        $this->set('distributionLevels', $distributionLevels);
    }

    /**
     * @param  mixed $id ID or UUID of the cluster
     */
    public function viewRelationTree($id, $includeInbound = 1)
    {
        $cluster = $this->GalaxyClusters->fetchIfAuthorized($this->ACL->getUser(), $id, 'view', $throwErrors = true, $full = true);
        $cluster = $this->GalaxyClusters->attachClusterToRelations($this->ACL->getUser()->toArray(), $cluster, $includeInbound);
        $grapher = new ClusterRelationsTreeTool();
        $grapher->construct($this->ACL->getUser()->toArray(), $this->GalaxyCluster);
        $tree = $grapher->getTree($cluster);
        $this->set('tree', $tree);
        $this->set('cluster', $cluster);
        $this->set('includeInbound', $includeInbound);
        $this->set('testtest', 'testtest');
        $this->render('/Elements/GalaxyClusters/view_relation_tree');
    }
}
