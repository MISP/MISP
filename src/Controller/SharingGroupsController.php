<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Model\Entity\SharingGroup;
use App\Model\Entity\SharingGroupOrg;
use App\Model\Entity\SharingGroupServer;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Validation\Validation;

class SharingGroupsController extends AppController
{
    use LocatorAwareTrait;

    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);
        if (!empty($this->request->getParam('admin')) && !$this->isSiteAdmin()) {
            $this->redirect('/');
        }
    }

    public $quickFilterFields = [['name' => true], 'uuid', ['releasability' => true], ['description' => true], ['Organisations.name' => true],];
    public $filterFields = [
        'name', 'uuid', 'releasability', 'description', 'active', 'created', 'modified', 'SharingGroups.local', 'roaming', ['name' => 'Organisations.name', 'multiple' => true],
    ];
    public $containFields = [
        'SharingGroupOrgs' => [
            'Organisations' => ['fields' => ['name', 'id', 'uuid']]
        ],
        'Organisations' => [
            'fields' => ['id', 'name', 'uuid'],
        ],
        'SharingGroupServers' => [
            'fields' => ['sharing_group_id', 'all_orgs'],
            'Servers' => [
                'fields' => ['name', 'id']
            ]
        ]
    ];
    public $statisticsFields = ['active', 'roaming'];

    public $paginate = [
        'limit' => 60,
        'maxLimit' => 9999,
        'order' => [
            'SharingGroup.name' => 'ASC'
        ],
        'fields' => ['id', 'uuid', 'name', 'description', 'releasability', 'local', 'active', 'roaming'],
        'contain' => [
            'SharingGroupOrgs' => [
                'Organisations' => ['fields' => ['name', 'id', 'uuid']]
            ],
            'Organisations' => [
                'fields' => ['id', 'name', 'uuid'],
            ],
            'SharingGroupServers' => [
                'fields' => ['sharing_group_id', 'all_orgs'],
                'Servers' => [
                    'fields' => ['name', 'id']
                ]
            ]
        ],
    ];
    public $wrapResponse = true;

    public function add()
    {
        $canModifyUuid = $this->ACL->getUser()->Role->perm_site_admin;

        if ($this->request->is('post')) {
            if ($this->ParamHandler->isRest()) {
                if (!empty($this->request->getData('SharingGroup'))) {
                    $data = $this->request->getData('SharingGroup');
                } else {
                    $data = $this->request->getData();
                }
                $sg = $data;
                $id = $this->SharingGroups->captureSG($sg, $this->ACL->getUser()->toArray());
                if ($id) {
                    if (empty($sg['roaming']) && empty($sg['SharingGroupServer'])) {
                        $sharingGroupServerEntity = $this->SharingGroups->SharingGroupServers->newEntity(
                            [
                                'sharing_group_id' => $id,
                                'server_id' => 0,
                                'all_orgs' => 0
                            ]
                        );
                        $this->SharingGroups->SharingGroupServers->save($sharingGroupServerEntity);
                    }
                    $sg = $this->SharingGroups->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'simplified', false, $id);
                    if (!empty($sg)) {
                        $sg = empty($sg) ? [] : $sg[0];
                    }
                    return $this->RestResponse->viewData($sg);
                } else {
                    return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.');
                }
            } else {
                $json = json_decode($this->request->getData('json'), true);
                $sg = $json['sharingGroup'];
                if (!empty($json['organisations'])) {
                    $sg['Organisation'] = $json['organisations'];
                }
                if (!empty($json['servers'])) {
                    $sg['Server'] = $json['servers'];
                }
            }
            if (!$canModifyUuid) {
                unset($sg['uuid']);
            }
            $sg['active'] = $sg['active'] ? 1 : 0;
            $sg['roaming'] = $sg['roaming'] ? 1 : 0;
            $sg['organisation_uuid'] = $this->ACL->getUser()->Organisation->uuid;
            $sg['local'] = 1;
            $sg['org_id'] = $this->ACL->getUser()->org_id;
            $sharingGroupEntity = $this->SharingGroups->newEntity($sg, ['associated' => []]);

            if ($this->SharingGroups->save($sharingGroupEntity, ['associated' => []])) { // Association will be saved manually
                if (!empty($sg['Organisation'])) {
                    foreach ($sg['Organisation'] as $org) {
                        $sharingGroupOrgEntity = $this->SharingGroups->SharingGroupOrgs->newEntity(
                            [
                                'sharing_group_id' => $sharingGroupEntity->id,
                                'org_id' => $org['id'],
                                'extend' => $org['extend']
                            ]
                        );
                        $this->SharingGroups->SharingGroupOrgs->save($sharingGroupOrgEntity);
                        $sharingGroupEntity->organisations[] = $sharingGroupOrgEntity;
                    }
                }
                if (empty($sg['roaming']) && !empty($sg['Server'])) {
                    foreach ($sg['Server'] as $server) {
                        $sharingGroupServerEntity = $this->SharingGroups->SharingGroupServers->newEntity(
                            [
                                'sharing_group_id' => $sharingGroupEntity->id,
                                'server_id' => $server['id'],
                                'all_orgs' => $server['all_orgs']
                            ]
                        );
                        $this->SharingGroups->SharingGroupServers->save($sharingGroupServerEntity);
                        $sharingGroupEntity->servers[] = $sharingGroupServerEntity;
                    }
                }
                $this->redirect('/sharing-groups/view/' . $sharingGroupEntity->id);
            } else {
                $validationErrors = $sharingGroupEntity->getErrors();
                $validationMessage = $this->CRUD->prepareValidationMessage($validationErrors);
                $message = __(
                    '{0} could not be added.{1}',
                    $this->SharingGroups->getAlias(),
                    empty($validationMessage) ? '' : PHP_EOL . __('Reason: {0}', $validationMessage)
                );
                $this->Flash->error($message);
            }
        } elseif ($this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('SharingGroup', 'add');
        }

        $organisations = $this->SharingGroups->Organisations->find()->all()->toList();
        $this->set('organisations', $organisations);
        $mispInstances = []; // TODO: [3.x-MIGRATION] Fill with servers when Server model is migrated
        $this->set('mispInstances', $mispInstances);
        $this->set('localInstance', empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl'));
        // We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
        $this->set('user', $this->ACL->getUser()->toArray());
        $this->set('canModifyUuid', $canModifyUuid);
    }

    public function edit($id = false)
    {
        if (empty($id)) {
            throw new NotFoundException('Invalid sharing group.');
        }

        // check if the user is eligible to edit the SG (original creator or extend)
        $sharingGroup = $this->SharingGroups->find(
            'all',
            [
                'conditions' => Validation::uuid($id) ? ['SharingGroups.uuid' => $id] : ['SharingGroups.id' => $id],
                'recursive' => -1,
                'contain' => [
                    'SharingGroupOrgs' => [
                        'Organisations' => [
                            'fields' => ['name', 'local', 'id', 'uuid']
                        ]
                    ],
                    'SharingGroupServers' => [
                        'Servers' => [
                            'fields' => ['name', 'url', 'id']
                        ]
                    ],
                    'Organisations' => [
                        'fields' => ['name', 'local', 'id']
                    ],
                ],
            ]
        )->first();

        if (empty($sharingGroup)) {
            throw new NotFoundException('Invalid sharing group.');
        }

        if (!$this->SharingGroups->checkIfAuthorisedExtend($this->ACL->getUser()->toArray(), $sharingGroup->id)) {
            throw new MethodNotAllowedException('Action not allowed.');
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if ($this->ParamHandler->isRest()) {
                if (!empty($this->request->getData('SharingGroup'))) {
                    $data = $this->request->getData('SharingGroup');
                } else {
                    $data = $this->request->getData();
                }
                $data['uuid'] = $sharingGroup->uuid;
                $id = $this->SharingGroups->captureSG($data, $this->ACL->getUser()->toArray());
                if ($id) {
                    $sg = $this->SharingGroups->fetchAllAuthorised($this->ACL->getUser()->toArray(), 'simplified', false, $id);
                    return $this->RestResponse->viewData($sg[0]);
                } else {
                    return $this->RestResponse->saveFailResponse('SharingGroup', 'edit', false, 'Could not save sharing group.');
                }
            } else {
                $json = json_decode($this->request->getData('json'), true);
                $sg = $json['sharingGroup'];
                $sg['id'] = $sharingGroup->id;
                $fields = ['name', 'releasability', 'description', 'active', 'roaming'];
                $existingSG = $sharingGroup;
                $existingSG = $this->SharingGroups->patchEntity($existingSG, $sg, ['fields' => $fields, 'associated' => []]);

                unset($existingSG['modified']);
                $existingSG = $this->SharingGroups->save($existingSG);
                if ($existingSG) {
                    $existingSGArray = $existingSG->toArray();
                    $this->SharingGroups->SharingGroupOrgs->updateOrgsForSG($existingSG->id, $json['organisations'], $existingSGArray['SharingGroupOrg'], $this->ACL->getUser()->toArray());
                    $this->SharingGroups->SharingGroupServers->updateServersForSG($existingSG->id, $json['servers'], $existingSGArray['SharingGroupServer'], $json['sharingGroup']['roaming'], $this->ACL->getUser()->toArray());
                    $this->redirect('/sharing-groups/view/' . $sharingGroup->id);
                } else {
                    $validationReplacements = [
                        'notempty' => 'This field cannot be left empty.',
                    ];
                    $validationErrors = $this->SharingGroups->validationErrors;
                    $failedField = array_keys($validationErrors)[0];
                    $reason = reset($this->SharingGroups->validationErrors)[0];
                    foreach ($validationReplacements as $k => $vR) {
                        if ($reason == $k) {
                            $reason = $vR;
                        }
                    }
                    $this->Flash->error('The sharing group could not be edited. ' . ucfirst($failedField) . ': ' . $reason);
                }
            }
        } elseif ($this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('SharingGroup', 'edit', false);
        }

        $this->set('entity', $sharingGroup);
        $this->set('id', $sharingGroup->id);
        $organisations = $this->SharingGroups->Organisations->find()->all()->toList();
        $this->set('organisations', $organisations);
        $mispInstances = []; // TODO: [3.x-MIGRATION] Fill with servers when Server model is migrated
        $this->set('mispInstances', $mispInstances);
        $this->set('localInstance', empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl'));
        // We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
        $this->set('user', $this->ACL->getUser()->toArray());
        $this->render('add');
    }

    public function delete($id=false)
    {
        $this->request->allowMethod(['get', 'post', 'delete']);
        $toggleParams = [
            'contain' => ['SharingGroupOrgs'],
            'tableFields' => [
                ['path' => 'id', 'label' => __('ID')],
                ['path' => 'name', 'label' => __('Name')],
                ['path' => 'releasability', 'label' => __('Releasability')],
                ['path' => 'active', 'label' => __('Active'), 'element' => 'boolean',],
                ['path' => 'roaming', 'label' => __('Roaming'), 'element' => 'boolean',],
                ['path' => 'org_count', 'label' => __('Org. count'), 'formatter' => function ($field, $row) {
                    return count($row['SharingGroupOrg']);
                }],
            ],
        ];
        $currentUser = $this->ACL->getUser();
        if (!$currentUser->Role->perm_admin) {
            $toggleParams['afterFind'] = function ($sg, &$params) use ($currentUser) {
                $authorizedSg = $this->SharingGroups->fetchSG($sg->id, $currentUser, false);
                if (empty($authorizedSg)) {
                    throw new MethodNotAllowedException(__('Invalid sharing group or no editing rights.'));
                }
                if (!$this->SharingGroups->checkIfOwner($currentUser->toArray(), $authorizedSg->id)) {
                    throw new MethodNotAllowedException(__('Action not allowed.'));
                }
                return $authorizedSg;
            };
        }
        $this->CRUD->delete($id, $toggleParams);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function index()
    {
        // TODO: [3.x-MIGRATION] fixme, cannot paginate on virtual fields
        $customContextFilters = [
            [
                'label' => __('Active Sharing Groups'),
                'filterCondition' => ['active' => 1]
            ],
            [
                'label' => __('Passive Sharing Groups'),
                'filterCondition' => ['active' => 0]
            ]
        ];

        $containFields = $this->containFields;
        $validFilterFields = $this->CRUD->getFilterFieldsName($this->filterFields);
        if (!$this->__showOrgs()) {
            $validFilterFields = array_filter($validFilterFields, fn($filter) => $filter != 'Organisations.name' );
            unset($containFields['SharingGroupOrgs']);
            unset($containFields['SharingGroupServers']);
        }

        $conditions = [];
        // Keep sharing group containing the requested orgs
        $params = $this->ParamHandler->harvestParams($validFilterFields);
        if ($this->__showOrgs() && !empty($params['Organisations.name'])) {
            $sgIDs = $this->SharingGroups->fetchSharingGroupIDsForOrganisations($params['Organisations.name']);
            if (empty($sgIDs)) {
                $sgIDs = -1;
            }
            $conditions['SharingGroups.id'] = $sgIDs;
        }

        // Check if the current user can modify or delete the SG
        $user = $this->ACL->getUser();
        $afterFindHandler = function ($sg) use ($user) {
            $sg = $this->SharingGroups->attachSharingGroupEditabilityForUser($sg, $user);
            return $sg;
        };

        $this->CRUD->index([
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields,
            'conditions' => $conditions,
            'contextFilters' => [
                'custom' => $customContextFilters,
            ],
            'contain' => $containFields,
            'afterFind' => $afterFindHandler,
            'statisticsFields' => $this->statisticsFields,
        ]);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function filtering()
    {
        $this->CRUD->filtering();
    }

    public function toggle($id, $fieldName = 'active')
    {
        $params = [];
        $currentUser = $this->ACL->getUser();
        if (!$currentUser->Role->perm_admin) {
            $params['afterFind'] = function ($sg, &$params) use ($currentUser, $id) {
                $authorizedSg = $this->SharingGroups->fetchSG($id, $currentUser, false);
                if (empty($authorizedSg)) {
                    throw new MethodNotAllowedException('Invalid sharing group or no editing rights.');
                }
                return $authorizedSg;
            };
        }
        $this->CRUD->toggle($id, $fieldName, $params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function massToggleField()
    {
        $validFields = ['roaming', 'active',];
        $toggleParams = [
            'contain' => ['SharingGroupOrgs'],
            'tableFields' => [
                ['path' => 'id', 'label' => __('ID')],
                ['path' => 'name', 'label' => __('Name')],
                ['path' => 'releasability', 'label' => __('Releasability')],
                ['path' => 'active', 'label' => __('Active'), 'element' => 'boolean',],
                ['path' => 'roaming', 'label' => __('Roaming'), 'element' => 'boolean',],
                ['path' => 'org_count', 'label' => __('Org. count'), 'formatter' => function ($field, $row) {
                    return count($row['SharingGroupOrg']);
                }],
            ],
        ];
        $requestParams = $this->ParamHandler->harvestParams($validFields);
        $fieldName = null;
        $toggleValue = null;
        foreach ($validFields as $field) {
            if (isset($requestParams[$field])) {
                $fieldName = $field;
                $toggleValue = $requestParams[$field];
                break;
            }
        }
        if (is_null($fieldName)) {
            throw new MethodNotAllowedException(__('Invalid field.'));
        }
        $toggleParams['force_state'] = $toggleValue;
        $currentUser = $this->ACL->getUser();
        if (!$currentUser->Role->perm_admin) {
            $toggleParams['afterFind'] = function ($sg, &$params) use ($currentUser) {
                $authorizedSg = $this->SharingGroups->fetchSG($sg->id, $currentUser, false);
                if (empty($authorizedSg)) {
                    throw new MethodNotAllowedException(__('Invalid sharing group or no editing rights.'));
                }
                return $authorizedSg;
            };
        }
        $this->CRUD->massToggle($fieldName, $toggleParams);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function view($id)
    {
        if ($this->request->is('head')) { // Just check if sharing group exists and user can access it
            $exists = $this->SharingGroups->checkIfAuthorised($this->ACL->getUser()->toArray(), $id);
            return new Response(['status' => $exists ? 200 : 404]);
        }
        if (!$this->SharingGroups->checkIfAuthorised($this->ACL->getUser()->toArray(), $id)) {
            throw new MethodNotAllowedException(__('Sharing group doesn\'t exist or you do not have permission to access it.'));
        }

        $contain = [
            'Organisations',
            'SharingGroupOrgs' => [
                'Organisations' => [
                    'fields' => ['id', 'name', 'uuid', 'local']
                ]
            ],
            'SharingGroupServers' => [
                'Servers' => [
                    'fields' => ['id', 'name', 'url']
                ]
            ]
        ];

        if (!$this->__showOrgs()) {
            unset($contain['SharingGroupOrgs']);
            unset($contain['SharingGroupServers']);
        }

        $afterFindHandler = function(SharingGroup $sg) {
            if (isset($sg->SharingGroupServer)) {
                foreach ($sg->SharingGroupServer as $key => $sgs) {
                    if ($sgs['server_id'] == 0) {
                        $sg->SharingGroupServer[$key]['Server'] = [
                            'id' => "0",
                            'name' => 'Local instance',
                            'url' => empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl')
                        ];
                    }
                }
            }
            if (!empty($sg->sync_user_id)) {
                $UserTable = $this->fetchTable('Users');
                $syncUser = $UserTable->find()->where([
                    'conditions' => ['Users.id' => $sg->sync_user_id],
                    'recursive' => -1,
                    'fields' => ['Users.id'],
                    'contain' => ['Organisations' => [
                        'fields' => ['Organisations.id', 'Organisations.name', 'Organisations.uuid'],
                    ]]
                ])->first();
                if (empty($syncUser)) {
                    $sg['sync_org_name'] = __('N/A');
                } else {
                    $sg['sync_org_name'] = $syncUser->Organisation->name;
                    $sg['sync_org'] = $syncUser->Organisation;
                }
            }

            $EventsTable = $this->fetchTable('Events');
            $conditions = $EventsTable->createEventConditions($this->ACL->getUser()->toArray());
            $conditions['AND']['sharing_group_id'] = $sg->id;
            $sg->event_count = $EventsTable->find()->where($conditions)->all()->count();
            return $sg;
        };

        $conditions= [];
        $params = [
            'contain' => $contain,
            'conditions' => $conditions,
            'afterFind' => $afterFindHandler,
        ];
        $this->CRUD->view($id, $params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    private function __initialiseSGQuickEdit($id, $request)
    {
        if (!$this->request->is('post') || !$this->ParamHandler->isRest()) {
            //throw new MethodNotAllowedException('This action only accepts POST requests coming from the API.');
        }
        // allow passing the sg_id via a JSON object
        if (!$id) {
            $validParams = ['sg_id', 'sg_uuid', 'id', 'uuid'];
            foreach ($validParams as $param) {
                if (!empty($request[$param])) {
                    $id = $request[$param];
                    break;
                }
            }
            if (empty($id)) {
                throw new MethodNotAllowedException('No valid sharing group ID provided.');
            }
        }
        $sg = $this->SharingGroups->fetchSG($id, $this->ACL->getUser()->toArray(), false);
        if (empty($sg)) {
            throw new MethodNotAllowedException('Invalid sharing group or no editing rights.');
        }
        return $sg;
    }

    private function __initialiseSGQuickEditObject($id, $request, $type = 'org')
    {
        $params = [
            'org' => [
                'org_id', 'org_uuid', 'org_name'
            ],
            'server' => [
                'server_id', 'server_url', 'server_baseurl', 'server_name'
            ]
        ];
        if (!empty($id)) {
            if ($type == 'org') {
                return $this->SharingGroups->SharingGroupOrgs->Organisations->fetchOrg($id);
            } else {
                return $this->SharingGroups->SharingGroupServers->Servers->fetchServer($id);
            }
        }
        if ($type !== 'org' && $type !== 'server') {
            return false;
        }
        foreach ($params[$type] as $param) {
            if (!empty($request[$param])) {
                if ($type == 'org') {
                    return $this->SharingGroups->SharingGroupOrgs->Organisations->fetchOrg($request[$param]);
                } else {
                    return $this->SharingGroups->SharingGroupServers->Servers->fetchServer($request[$param]);
                }
            }
        }
    }

    public function addOrg($sg_id = false, $object_id = false, $extend = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->getData());
        $org = $this->__initialiseSGQuickEditObject($object_id, $this->request->getData(), $type = 'org');
        if (empty($org)) {
            throw new MethodNotAllowedException('Invalid organisation.');
        }
        if (!empty($this->request->getData('extend'))) {
            $extend = $this->request->getData('extend');
        }
        $addOrg = true;
        if (!empty($sg['SharingGroupOrg'])) {
            foreach ($sg['SharingGroupOrg'] as $sgo) {
                if ($sgo['org_id'] == $org['id']) {
                    $addOrg = false;
                }
            }
        }
        if (!$addOrg) {
            return $this->RestResponse->saveFailResponse('SharingGroup', 'addOrg', false, 'Organisation is already in the sharing group.');
        }
        $sharingGroupOrgEntity = new SharingGroupOrg(
            [
                'org_id' => $org['id'],
                'sharing_group_id' => $sg['id'],
                'extend' => $extend ? 1 : 0
            ]
        );

        $result = $this->SharingGroups->SharingGroupOrgs->save($sharingGroupOrgEntity);
        return $this->__sendQuickSaveResponse('addOrg', $result, 'Organisation');
    }

    public function removeOrg($sg_id = false, $object_id = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->getData());
        $org = $this->__initialiseSGQuickEditObject($object_id, $this->request->getData(), $type = 'org');
        if (empty($org)) {
            throw new MethodNotAllowedException('Invalid organisation.');
        }
        $removeOrg = false;
        if (!empty($sg['SharingGroupOrg'])) {
            foreach ($sg['SharingGroupOrg'] as $sgo) {
                if ($sgo['org_id'] == $org['id']) {
                    $removeOrg = $sgo['id'];
                    break;
                }
            }
        }
        if (false === $removeOrg) {
            return $this->RestResponse->saveFailResponse('SharingGroup', 'removeOrg', false, 'Organisation is not in the sharing group.');
        }
        $orgEntity = $this->SharingGroups->SharingGroupOrgs->get($removeOrg);
        $result = $this->SharingGroups->SharingGroupOrgs->delete($orgEntity);
        return $this->__sendQuickSaveResponse('removeOrg', $result, 'Organisation');
    }

    public function addServer($sg_id = false, $object_id = false, $all = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->getData());
        $server = $this->__initialiseSGQuickEditObject($object_id, $this->request->getData(), $type = 'server');
        if (empty($server)) {
            throw new MethodNotAllowedException('Invalid Server.');
        }
        if (!empty($this->request->getData('all'))) {
            $all = $this->request->getData('all');
        }
        if (!empty($this->request->getData('all_orgs'))) {
            $all = $this->request->getData('all_orgs');
        }
        $addServer = true;
        if (!empty($sg['SharingGroupServer'])) {
            foreach ($sg['SharingGroupServer'] as $sgs) {
                if ($sgs['server_id'] == $server['id']) {
                    $addServer = false;
                }
            }
        }
        if (!$addServer) {
            return $this->RestResponse->saveFailResponse('SharingGroup', 'addServer', false, 'Server is already in the sharing group.');
        }
        $sharingGroupServerEntity = new SharingGroupServer(
            [
                'server_id' => $server['id'],
                'sharing_group_id' => $sg['id'],
                'all_orgs' => $all ? 1 : 0
            ]
        );
        $result = $this->SharingGroups->SharingGroupServers->save($sharingGroupServerEntity);
        return $this->__sendQuickSaveResponse('addServer', $result);
    }

    public function removeServer($sg_id = false, $object_id = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->getData());
        $server = $this->__initialiseSGQuickEditObject($object_id, $this->request->getData(), $type = 'server');
        if (empty($server)) {
            throw new MethodNotAllowedException('Invalid Server.');
        }
        $removeServer = false;
        if (!empty($sg['SharingGroupServer'])) {
            foreach ($sg['SharingGroupServer'] as $sgs) {
                if ($sgs['server_id'] == $server['id']) {
                    $removeServer = $sgs['id'];
                    break;
                }
            }
        }
        if (false === $removeServer) {
            return $this->RestResponse->saveFailResponse('SharingGroup', 'removeServer', false, 'Server is not in the sharing group.');
        }
        $serverEntity = $this->SharingGroups->SharingGroupServers->get($removeServer);
        $result = $this->SharingGroups->SharingGroupServers->delete($serverEntity);
        return $this->__sendQuickSaveResponse('removeServer', $result);
    }

    private function __sendQuickSaveResponse($action, $result, $object_type = 'Server')
    {
        $actionType = 'added to';
        if (strpos($action, 'remove') !== false) {
            $actionType = 'removed from';
        }
        if ($result) {
            return $this->RestResponse->saveSuccessResponse('SharingGroup', $action, false, 'json', $object_type . ' ' . $actionType . ' the sharing group.');
        } else {
            return $this->RestResponse->saveFailResponse('SharingGroup', $action, false, $object_type . ' could not be ' . $actionType . ' the sharing group.');
        }
    }

    /**
     * @return bool
     */
    private function __showOrgs(): bool
    {
        return $this->ACL->getUser()->Role->perm_sharing_group || !Configure::read('Security.hide_organisations_in_sharing_groups');
    }
}
