<?php

namespace App\Controller;

use App\Controller\AppController;
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

    public function add()
    {
        $canModifyUuid = $this->ACL->getUser()->Role->perm_site_admin;

        if ($this->request->is('post')) {
            if ($this->ParamHandler->isRest()) {
                if (!empty($this->request->getData('SharingGroup'))) {
                    $data = $this->request->getData('SharingGroup');
                }
                $sg = $data;
                $id = $this->SharingGroups->captureSG($sg, $this->ACL->getUser());
                if ($id) {
                    if (empty($sg['roaming']) && empty($sg['SharingGroupServer'])) {
                        $this->SharingGroups->SharingGroupServers->create();
                        $this->SharingGroups->SharingGroupServers->save(
                            [
                                'sharing_group_id' => $this->SharingGroups->id,
                                'server_id' => 0,
                                'all_orgs' => 0
                            ]
                        );
                    }
                    $sg = $this->SharingGroups->fetchAllAuthorised($this->ACL->getUser(), 'simplified', false, $id);
                    if (!empty($sg)) {
                        $sg = empty($sg) ? [] : $sg[0];
                    }
                    return $this->RestResponse->viewData($sg, $this->response->getType());
                } else {
                    return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.', $this->response->getType());
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
            $this->SharingGroups->create();
            if (!$canModifyUuid) {
                unset($sg['uuid']);
            }
            $sg['active'] = $sg['active'] ? 1 : 0;
            $sg['roaming'] = $sg['roaming'] ? 1 : 0;
            $sg['organisation_uuid'] = $this->ACL->getUser()->Organisation->uuid;
            $sg['local'] = 1;
            $sg['org_id'] = $this->ACL->getUser()->org_id;
            if ($this->SharingGroups->save(['SharingGroup' => $sg])) {
                if (!empty($sg['Organisation'])) {
                    foreach ($sg['Organisation'] as $org) {
                        $this->SharingGroups->SharingGroupOrgs->create();
                        $this->SharingGroups->SharingGroupOrgs->save(
                            [
                                'sharing_group_id' => $this->SharingGroups->id,
                                'org_id' => $org['id'],
                                'extend' => $org['extend']
                            ]
                        );
                    }
                }
                if (empty($sg['roaming']) && !empty($sg['Server'])) {
                    foreach ($sg['Server'] as $server) {
                        $this->SharingGroups->SharingGroupServers->create();
                        $this->SharingGroups->SharingGroupServers->save(
                            [
                                'sharing_group_id' => $this->SharingGroups->id,
                                'server_id' => $server['id'],
                                'all_orgs' => $server['all_orgs']
                            ]
                        );
                    }
                }
                $this->redirect('/SharingGroups/view/' . $this->SharingGroups->id);
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
                $this->Flash->error('The sharing group could not be added. ' . ucfirst($failedField) . ': ' . $reason);
            }
        } elseif ($this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('SharingGroup', 'add', false, $this->response->getType());
        }

        $this->set('localInstance', empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl'));
        // We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
        $this->set('user', $this->ACL->getUser());
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
                            'fields' => ['name', 'local', 'id']
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
        )->disableHydration()->first();

        if (empty($sharingGroup)) {
            throw new NotFoundException('Invalid sharing group.');
        }

        if (!$this->SharingGroups->checkIfAuthorisedExtend($this->ACL->getUser()->toArray(), $sharingGroup['id'])) {
            throw new MethodNotAllowedException('Action not allowed.');
        }
        if ($this->request->is('post')) {
            if ($this->ParamHandler->isRest()) {
                if (!empty($this->request->getData('SharingGroup'))) {
                    $data = $this->request->getData('SharingGroup');
                }
                $data['uuid'] = $sharingGroup['uuid'];
                $id = $this->SharingGroups->captureSG($data, $this->ACL->getUser());
                if ($id) {
                    $sg = $this->SharingGroups->fetchAllAuthorised($this->ACL->getUser(), 'simplified', false, $id);
                    return $this->RestResponse->viewData($sg[0], $this->response->getType());
                } else {
                    return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.', $this->response->getType());
                }
            } else {
                $json = json_decode($this->request->getData('json'), true);
                $sg = $json['sharingGroup'];
                $sg['id'] = $sharingGroup['id'];
                $fields = ['name', 'releasability', 'description', 'active', 'roaming'];
                $existingSG = $this->SharingGroups->find('all', ['recursive' => -1, 'conditions' => ['SharingGroup.id' => $sharingGroup['id']]])->disableHydration()->first();
                foreach ($fields as $field) {
                    $existingSG[$field] = $sg[$field];
                }
                unset($existingSG['modified']);
                if ($this->SharingGroups->save($existingSG)) {
                    $this->SharingGroups->SharingGroupOrgs->updateOrgsForSG($sharingGroup['id'], $json['organisations'], $sharingGroup['SharingGroupOrg'], $this->ACL->getUser());
                    $this->SharingGroups->SharingGroupServers->updateServersForSG($sharingGroup['id'], $json['servers'], $sharingGroup['SharingGroupServer'], $json['sharingGroup']['roaming'], $this->ACL->getUser());
                    $this->redirect('/SharingGroups/view/' . $sharingGroup['id']);
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
            return $this->RestResponse->describe('SharingGroup', 'edit', false, $this->response->getType());
        }
        $orgs = $this->SharingGroups->Organisations->find(
            'all',
            [
                'conditions' => ['local' => 1],
                'recursive' => -1,
                'fields' => ['id', 'name']
            ]
        )->disableHydration()->toArray();
        
        $this->set('entity', $sharingGroup);
        $this->set('id', $sharingGroup['id']);
        $this->set('orgs', $orgs);
        $this->set('localInstance', empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl'));
        // We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
        $this->set('user', $this->ACL->getUser());
    }

    public function delete($id)
    {
        $this->request->allowMethod(['post', 'delete']);

        $deletedSg = $this->SharingGroups->find(
            'all',
            [
                'conditions' => Validation::uuid($id) ? ['uuid' => $id] : ['id' => $id],
                'recursive' => -1,
                'fields' => ['id', 'active'],
            ]
        )->disableHydration()->first();
        if (empty($deletedSg) || !$this->SharingGroups->checkIfOwner($this->ACL->getUser(), $deletedSg['id'])) {
            throw new MethodNotAllowedException('Action not allowed.');
        }
        if ($this->SharingGroups->delete($deletedSg['id'])) {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('SharingGroups', 'delete', $id, $this->response->getType());
            }
            $this->Flash->success(__('Sharing Group deleted'));
        } else {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveFailResponse('SharingGroups', 'delete', $id, 'The sharing group could not be deleted.', $this->response->getType());
            }
            $this->Flash->error(__('Sharing Group could not be deleted. Make sure that there are no events, attributes or threads belonging to this sharing group.'));
        }

        if ($deletedSg['active']) {
            $this->redirect('/SharingGroups/index');
        } else {
            $this->redirect('/SharingGroups/index/true');
        }
    }

    public function index($passive = false)
    {
        $passive = $passive === 'true';
        $authorizedSgIds = $this->SharingGroups->authorizedIds($this->ACL->getUser()->toArray());
        // TODO: [3.x-MIGRATION] fix this array conversion
        // $this->paginate['conditions'][] = ['id' => $authorizedSgIds];
        // $this->paginate['conditions'][] = ['active' => $passive === true ? 0 : 1];

        if (!empty($this->request->getParam('value'))) {
            $term = '%' . strtolower($this->request->getParam('value')) . '%';
            if ($this->__showOrgs()) {
                $sgIds = $this->SharingGroups->SharingGroupOrgs->find(
                    'column',
                    [
                        'conditions' => [
                            'OR' => [
                                'Organisations.uuid LIKE' => $term,
                                'LOWER(Organisations.name) LIKE' => $term,
                            ],
                            'SharingGroupOrg.sharing_group_id' => $authorizedSgIds,
                        ],
                        'contain' => ['Organisations'],
                        'fields' => ['SharingGroupOrgs.sharing_group_id'],
                    ]
                );
            } else {
                $sgIds = [];
            }
            $this->paginate['conditions'][]['OR'] = [
                'id' => $sgIds,
                'uuid LIKE' => $term,
                'LOWER(name) LIKE' => $term,
                'LOWER(description) LIKE' => $term,
                'LOWER(releasability) LIKE' => $term,
                'LOWER(Organisations.name) LIKE' => $term,
            ];
        }

        if ($this->__showOrgs() && !empty($this->request->getParam('searchorg'))) {
            $orgs = explode('|', $this->request->getParam('searchorg'));
            $conditions = [];
            foreach ($orgs as $org) {
                $exclude = $org[0] === '!';
                if ($exclude) {
                    $org = substr($org, 1);
                }
                $org = $this->SharingGroups->Organisations->fetchOrg($org);
                if ($org) {
                    if ($exclude) {
                        $conditions['AND'][] = ['org_id !=' => $org['id']];
                    } else {
                        $conditions['OR'][] = ['org_id' => $org['id']];
                    }
                }
            }
            $sgIds = $this->SharingGroups->SharingGroupOrgs->find(
                'column',
                [
                    'conditions' => $conditions,
                    'fields' => ['SharingGroupOrgs.sharing_group_id'],
                ]
            );
            if (empty($sgIds)) {
                $sgIds = -1;
            }
            $this->paginate['conditions'][] = ['id' => $sgIds];
        }

        // To allow sort sharing group by number of organisation and also show org count when user don't have permission ot see them
        // TODO: [3.x-MIGRATION] fixme, cannot paginate on virtual fields
        // $this->paginate['fields'][] = 'SharingGroup.org_count';

        if (!$this->__showOrgs()) {
            unset($this->paginate['contain']['SharingGroupOrgs']);
            unset($this->paginate['contain']['SharingGroupServers']);
        }

        $result = $this->paginate()->toArray();

        // check if the current user can modify or delete the SG
        $userOrganisationUuid = $this->ACL->getUser()->Organisation['uuid'];
        $response = [];
        foreach ($result as $k => $sg) {
            $sg = $sg->toArray();
            $editable = false;
            $deletable = false;

            if ($this->ACL->getUser()->Role->perm_site_admin || ($this->ACL->getUser()->Role->perm_sharing_group && $sg['Organisation']['uuid'] === $userOrganisationUuid)) {
                $editable = true;
                $deletable = true;
            } else if ($this->ACL->getUser()->Role->perm_sharing_group) {
                if (!empty($sg['SharingGroupOrgs'])) {
                    foreach ($sg['SharingGroupOrgs'] as $sgo) {
                        if ($sgo['extend'] && $sgo['org_id'] == $this->Auth->user('org_id')) {
                            $editable = true;
                            break;
                        }
                    }
                }
            }

            $response[$k] = $sg;
            $response[$k]['editable'] = $editable;
            $response[$k]['deletable'] = $deletable;
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(['response' => $response], $this->response->getType()); // 'response' to keep BC
        }
        $this->set('passive', $passive);
        $this->set('sharingGroups', $response);
        $this->set('passedArgs', $passive ? 'true' : '[]');
        $this->set('title_for_layout', __('Sharing Groups'));
    }

    public function view($id)
    {
        if ($this->request->is('head')) { // Just check if sharing group exists and user can access it
            $exists = $this->SharingGroups->checkIfAuthorised($this->ACL->getUser(), $id);
            return new Response(['status' => $exists ? 200 : 404]);
        }
        if (!$this->SharingGroups->checkIfAuthorised($this->ACL->getUser(), $id)) {
            throw new MethodNotAllowedException('Sharing group doesn\'t exist or you do not have permission to access it.');
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

        $sg = $this->SharingGroups->find(
            'all',
            [
                'conditions' => Validation::uuid($id) ? ['SharingGroups.uuid' => $id] : ['SharingGroups.id' => $id],
                'contain' => $contain,
            ]
        )->disableHydration()->first();
        if (isset($sg['SharingGroupServer'])) {
            foreach ($sg['SharingGroupServer'] as $key => $sgs) {
                if ($sgs['server_id'] == 0) {
                    $sg['SharingGroupServer'][$key]['Server'] = [
                        'id' => "0",
                        'name' => 'Local instance',
                        'url' => empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl')
                    ];
                }
            }
        }
        if ($sg['sync_user_id']) {
            $UserTable = $this->fetchTable('Users');
            $syncUser = $UserTable->find(
                'all',
                [
                    'conditions' => ['Users.id' => $sg['sync_user_id']],
                    'recursive' => -1,
                    'fields' => ['Users.id'],
                    'contain' => ['Organisations' => [
                        'fields' => ['Organisations.id', 'Organisations.name', 'Organisations.uuid'],
                    ]]
                ]
            )->disableHydration()->first();
            if (empty($syncUser)) {
                $sg['sync_org_name'] = 'N/A';
            } else {
                $sg['sync_org_name'] = $syncUser['Organisation']['name'];
                $sg['sync_org'] = $syncUser['Organisation'];
            }
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($sg, $this->response->getType());
        }

        $EventsTable = $this->fetchTable('Events');
        $conditions = $EventsTable->createEventConditions($this->ACL->getUser()->toArray());
        $conditions['AND']['sharing_group_id'] = $sg['id'];
        $sg['event_count'] = $EventsTable->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1,
                'callbacks' => false,
            ]
        )->count();

        $this->set('mayModify', $this->SharingGroups->checkIfAuthorisedExtend($this->ACL->getUser()->toArray(), $sg['id']));
        $this->set('id', $sg['id']);
        $this->set('entity', $sg);
        $this->set('menuData', ['menuList' => 'globalActions', 'menuItem' => 'viewSG']);
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
        $sg = $this->SharingGroups->fetchSG($id, $this->ACL->getUser(), false);
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
                return $this->SharingGroups->SharingGroupOrgs->Organisation->fetchOrg($id);
            } else {
                return $this->SharingGroups->SharingGroupServers->Server->fetchServer($id);
            }
        }
        if ($type !== 'org' && $type !== 'server') {
            return false;
        }
        foreach ($params[$type] as $param) {
            if (!empty($request[$param])) {
                if ($type == 'org') {
                    return $this->SharingGroups->SharingGroupOrgs->Organisation->fetchOrg($request[$param]);
                } else {
                    return $this->SharingGroups->SharingGroupServers->Server->fetchServer($request[$param]);
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
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Organisation is already in the sharing group.', $this->response->getType());
        }
        $this->SharingGroups->SharingGroupOrgs->create();
        $sgo = [
            'SharingGroupOrg' => [
                'org_id' => $org['id'],
                'sharing_group_id' => $sg['id'],
                'extend' => $extend ? 1 : 0
            ]
        ];
        $result = $this->SharingGroups->SharingGroupOrgs->save($sgo);
        return $this->__sendQuickSaveResponse($this->action, $result, 'Organisation');
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
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Organisation is not in the sharing group.', $this->response->getType());
        }
        $result = $this->SharingGroups->SharingGroupOrgs->delete($removeOrg);
        return $this->__sendQuickSaveResponse($this->action, $result, 'Organisation');
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
                if ($sgs['server_id'] == $server['Server']['id']) {
                    $addServer = false;
                }
            }
        }
        if (!$addServer) {
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Server is already in the sharing group.', $this->response->getType());
        }
        $this->SharingGroups->SharingGroupServers->create();
        $sgs = [
            'SharingGroupServer' => [
                'server_id' => $server['Server']['id'],
                'sharing_group_id' => $sg['id'],
                'all_orgs' => $all ? 1 : 0
            ]
        ];
        $result = $this->SharingGroups->SharingGroupServers->save($sgs);
        return $this->__sendQuickSaveResponse($this->action, $result);
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
                if ($sgs['server_id'] == $server['Server']['id']) {
                    $removeServer = $server['Server']['id'];
                    break;
                }
            }
        }
        if (false === $removeServer) {
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Server is not in the sharing group.', $this->response->getType());
        }
        $result = $this->SharingGroups->SharingGroupServers->delete($removeServer);
        return $this->__sendQuickSaveResponse($this->action, $result);
    }

    private function __sendQuickSaveResponse($action, $result, $object_type = 'Server')
    {
        $actionType = 'added to';
        if (strpos($action, 'remove') !== false) {
            $actionType = 'removed from';
        }
        if ($result) {
            return $this->RestResponse->saveSuccessResponse('SharingGroup', $action, false, $this->response->getType(), $object_type . ' ' . $actionType . ' the sharing group.');
        } else {
            return $this->RestResponse->saveFailResponse('SharingGroup', $action, false, $object_type . ' could not be ' . $actionType . ' the sharing group.', $this->response->getType());
        }
    }

    /**
     * @return bool
     */
    private function __showOrgs()
    {
        return $this->ACL->getUser()->Role->perm_sharing_group || !Configure::read('Security.hide_organisations_in_sharing_groups');
    }
}
