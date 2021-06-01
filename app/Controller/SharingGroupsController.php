<?php
App::uses('AppController', 'Controller');

/**
 * @property SharingGroup $SharingGroup
 */
class SharingGroupsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!empty($this->request->params['admin']) && !$this->_isSiteAdmin()) {
            $this->redirect('/');
        }
    }

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
        'order' => array(
            'SharingGroup.name' => 'ASC'
        ),
        'fields' => array('SharingGroup.id', 'SharingGroup.uuid', 'SharingGroup.name', 'SharingGroup.description', 'SharingGroup.releasability', 'SharingGroup.local', 'SharingGroup.active', 'SharingGroup.roaming'),
        'contain' => array(
            'SharingGroupOrg' => array(
                'Organisation' => array('fields' => array('Organisation.name', 'Organisation.id', 'Organisation.uuid'))
            ),
            'Organisation' => array(
                'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'),
            ),
            'SharingGroupServer' => array(
                'fields' => array('SharingGroupServer.all_orgs'),
                'Server' => array(
                    'fields' => array('Server.name', 'Server.id')
                )
            )
        ),
    );

    public function add()
    {
        if (!$this->userRole['perm_sharing_group']) {
            throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
        }
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                if (isset($this->request->data['SharingGroup'])) {
                    $this->request->data = $this->request->data['SharingGroup'];
                }
                $sg = $this->request->data;
                $id = $this->SharingGroup->captureSG($this->request->data, $this->Auth->user());
                if ($id) {
                    if (empty($sg['roaming']) && empty($sg['SharingGroupServer'])) {
                       $this->SharingGroup->SharingGroupServer->create();
                       $this->SharingGroup->SharingGroupServer->save(array(
                               'sharing_group_id' => $this->SharingGroup->id,
                               'server_id' => 0,
                               'all_orgs' => 0
                       ));
                   }
                    $sg = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'simplified', false, $id);
                    if (!empty($sg)) {
                        $sg = empty($sg) ? array() : $sg[0];
                    }
                    return $this->RestResponse->viewData($sg, $this->response->type());
                } else {
                    return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.', $this->response->type());
                }
            } else {
                $json = json_decode($this->request->data['SharingGroup']['json'], true);
                $sg = $json['sharingGroup'];
                if (!empty($json['organisations'])) {
                    $sg['Organisation'] = $json['organisations'];
                }
                if (!empty($json['servers'])) {
                    $sg['Server'] = $json['servers'];
                }
            }
            $this->SharingGroup->create();
            $sg['active'] = $sg['active'] ? 1: 0;
            $sg['roaming'] = $sg['roaming'] ? 1: 0;
            $sg['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
            $sg['local'] = 1;
            $sg['org_id'] = $this->Auth->user('org_id');
            $this->request->data['SharingGroup']['organisation_uuid'] = $this->Auth->user('Organisation')['uuid'];
            if ($this->SharingGroup->save(array('SharingGroup' => $sg))) {
                if (!empty($sg['Organisation'])) {
                    foreach ($sg['Organisation'] as $org) {
                        $this->SharingGroup->SharingGroupOrg->create();
                        $this->SharingGroup->SharingGroupOrg->save(array(
                                'sharing_group_id' => $this->SharingGroup->id,
                                'org_id' => $org['id'],
                                'extend' => $org['extend']
                        ));
                    }
                }
                if (empty($sg['roaming']) && !empty($sg['Server'])) {
                    foreach ($sg['Server'] as $server) {
                        $this->SharingGroup->SharingGroupServer->create();
                        $this->SharingGroup->SharingGroupServer->save(array(
                                'sharing_group_id' => $this->SharingGroup->id,
                                'server_id' => $server['id'],
                                'all_orgs' => $server['all_orgs']
                        ));
                    }
                }
                $this->redirect('/SharingGroups/view/' . $this->SharingGroup->id);
            } else {
                $validationReplacements = array(
                    'notempty' => 'This field cannot be left empty.',
                );
                $validationErrors = $this->SharingGroup->validationErrors;
                $failedField = array_keys($validationErrors)[0];
                $reason = reset($this->SharingGroup->validationErrors)[0];
                foreach ($validationReplacements as $k => $vR) {
                    if ($reason == $k) {
                        $reason = $vR;
                    }
                }
                $this->Flash->error('The sharing group could not be added. ' . ucfirst($failedField) . ': ' . $reason);
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('SharingGroup', 'add', false, $this->response->type());
        }

        $orgs = $this->SharingGroup->Organisation->find('all', array(
            'conditions' => array('local' => 1),
            'recursive' => -1,
            'fields' => array('id', 'name', 'uuid')
        ));
        $this->set('orgs', $orgs);
        $this->set('localInstance', empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl'));
        // We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
        $this->set('user', $this->Auth->user());
    }

    public function edit($id = false)
    {
        if (!$this->userRole['perm_sharing_group']) {
            throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
        }
        if (empty($id)) {
            throw new NotFoundException('Invalid sharing group.');
        }

        // check if the user is eligible to edit the SG (original creator or extend)
        $sharingGroup = $this->SharingGroup->find('first', array(
            'conditions' => Validation::uuid($id) ? ['SharingGroup.uuid' => $id] : ['SharingGroup.id' => $id],
            'recursive' => -1,
            'contain' => array(
                'SharingGroupOrg' => array(
                    'Organisation' => array('name', 'local', 'id')
                ),
                'SharingGroupServer' => array(
                    'Server' => array(
                        'fields' => array('name', 'url', 'id')
                    )
                ),
                'Organisation' => array(
                    'fields' => array('name', 'local', 'id')
                ),
            ),
        ));
        if (!$this->SharingGroup->checkIfAuthorisedExtend($this->Auth->user(), $sharingGroup['SharingGroup']['id'])) {
            throw new MethodNotAllowedException('Action not allowed.');
        }
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                if (isset($this->request->data['SharingGroup'])) {
                    $this->request->data = $this->request->data['SharingGroup'];
                }
                $this->request->data['uuid'] = $sharingGroup['SharingGroup']['uuid'];
                $id = $this->SharingGroup->captureSG($this->request->data, $this->Auth->user());
                if ($id) {
                    $sg = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'simplified', false, $id);
                    return $this->RestResponse->viewData($sg[0], $this->response->type());
                } else {
                    return $this->RestResponse->saveFailResponse('SharingGroup', 'add', false, 'Could not save sharing group.', $this->response->type());
                }
            } else {
                $json = json_decode($this->request->data['SharingGroup']['json'], true);
                $sg = $json['sharingGroup'];
                $sg['id'] = $sharingGroup['SharingGroup']['id'];
                $fields = array('name', 'releasability', 'description', 'active', 'roaming');
                $existingSG = $this->SharingGroup->find('first', array('recursive' => -1, 'conditions' => array('SharingGroup.id' => $sharingGroup['SharingGroup']['id'])));
                foreach ($fields as $field) {
                    $existingSG['SharingGroup'][$field] = $sg[$field];
                }
                unset($existingSG['SharingGroup']['modified']);
                if ($this->SharingGroup->save($existingSG)) {
                    $this->SharingGroup->SharingGroupOrg->updateOrgsForSG($sharingGroup['SharingGroup']['id'], $json['organisations'], $sharingGroup['SharingGroupOrg'], $this->Auth->user());
                    $this->SharingGroup->SharingGroupServer->updateServersForSG($sharingGroup['SharingGroup']['id'], $json['servers'], $sharingGroup['SharingGroupServer'], $json['sharingGroup']['roaming'], $this->Auth->user());
                    $this->redirect('/SharingGroups/view/' . $sharingGroup['SharingGroup']['id']);
                } else {
                    $validationReplacements = array(
                        'notempty' => 'This field cannot be left empty.',
                    );
                    $validationErrors = $this->SharingGroup->validationErrors;
                    $failedField = array_keys($validationErrors)[0];
                    $reason = reset($this->SharingGroup->validationErrors)[0];
                    foreach ($validationReplacements as $k => $vR) {
                        if ($reason == $k) {
                            $reason = $vR;
                        }
                    }
                    $this->Flash->error('The sharing group could not be edited. ' . ucfirst($failedField) . ': ' . $reason);
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('SharingGroup', 'edit', false, $this->response->type());
        }
        $orgs = $this->SharingGroup->Organisation->find('all', array(
            'conditions' => array('local' => 1),
            'recursive' => -1,
            'fields' => array('id', 'name')
        ));
        $this->set('sharingGroup', $sharingGroup);
        $this->set('id', $sharingGroup['SharingGroup']['id']);
        $this->set('orgs', $orgs);
        $this->set('localInstance', empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl'));
        // We just pass true and allow the user to edit, since he/she is just about to create the SG. This is needed to reuse the view for the edit
        $this->set('user', $this->Auth->user());
    }

    public function delete($id)
    {
        if (!$this->userRole['perm_sharing_group']) {
            throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
        }
        if (!$this->request->is('post') && !$this->request->is('delete')) {
            throw new MethodNotAllowedException(__('Action not allowed, post or delete request expected.'));
        }
        $deletedSg = $this->SharingGroup->find('first', array(
            'conditions' => Validation::uuid($id) ? ['uuid' => $id] : ['id' => $id],
            'recursive' => -1,
            'fields' => ['id', 'active'],
        ));
        if (empty($deletedSg) || !$this->SharingGroup->checkIfOwner($this->Auth->user(), $deletedSg['SharingGroup']['id'])) {
            throw new MethodNotAllowedException('Action not allowed.');
        }
        if ($this->SharingGroup->delete($deletedSg['SharingGroup']['id'])) {
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('SharingGroups', 'delete', $id, $this->response->type());
            }
            $this->Flash->success(__('Sharing Group deleted'));
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('SharingGroups', 'delete', $id, 'The sharing group could not be deleted.', $this->response->type());
            }
            $this->Flash->error(__('Sharing Group could not be deleted. Make sure that there are no events, attributes or threads belonging to this sharing group.'));
        }

        if ($deletedSg['SharingGroup']['active']) {
            $this->redirect('/SharingGroups/index');
        } else {
            $this->redirect('/SharingGroups/index/true');
        }
    }

    public function index($passive = false)
    {
        $passive = $passive === 'true';
        $authorizedSgIds = $this->SharingGroup->fetchAllAuthorised($this->Auth->user());
        $this->paginate['conditions'][] = array('SharingGroup.id' => $authorizedSgIds);
        $this->paginate['conditions'][] = array('SharingGroup.active' => $passive === true ? 0 : 1);

        if (isset($this->params['named']['value'])) {
            $term = '%' . strtolower($this->params['named']['value']) . '%';
            if ($this->__showOrgs()) {
                $sgIds = $this->SharingGroup->SharingGroupOrg->find('column', [
                    'conditions' => [
                        'OR' => [
                            'Organisation.uuid LIKE' => $term,
                            'LOWER(Organisation.name) LIKE' => $term,
                        ],
                        'SharingGroupOrg.sharing_group_id' => $authorizedSgIds,
                    ],
                    'contain' => ['Organisation'],
                    'fields' => ['SharingGroupOrg.sharing_group_id'],
                ]);
            } else {
                $sgIds = [];
            }
            $this->paginate['conditions'][]['OR'] = [
                'SharingGroup.id' => $sgIds,
                'SharingGroup.uuid LIKE' => $term,
                'LOWER(SharingGroup.name) LIKE' => $term,
                'LOWER(SharingGroup.description) LIKE' => $term,
                'LOWER(SharingGroup.releasability) LIKE' => $term,
                'LOWER(Organisation.name) LIKE' => $term,
            ];
        }

        if ($this->__showOrgs() && isset($this->params['named']['searchorg'])) {
            $orgs = explode('|', $this->params['named']['searchorg']);
            $conditions = [];
            foreach ($orgs as $org) {
                $exclude = $org[0] === '!';
                if ($exclude) {
                    $org = substr($org, 1);
                }
                $org = $this->SharingGroup->Organisation->fetchOrg($org);
                if ($org) {
                    if ($exclude) {
                        $conditions['AND'][] = ['org_id !=' => $org['id']];
                    } else {
                        $conditions['OR'][] = ['org_id' => $org['id']];
                    }
                }
            }
            $sgIds = $this->SharingGroup->SharingGroupOrg->find('column', [
                'conditions' => $conditions,
                'fields' => ['SharingGroupOrg.sharing_group_id'],
            ]);
            if (empty($sgIds)) {
                $sgIds = -1;
            }
            $this->paginate['conditions'][] = ['SharingGroup.id' => $sgIds];
        }

        // To allow sort sharing group by number of organisation and also show org count when user don't have permission ot see them
        $this->SharingGroup->addCountField('org_count', $this->SharingGroup->SharingGroupOrg, ['SharingGroupOrg.sharing_group_id = SharingGroup.id']);
        $this->paginate['fields'][] = 'SharingGroup.org_count';

        if (!$this->__showOrgs()) {
            unset($this->paginate['contain']['SharingGroupOrg']);
            unset($this->paginate['contain']['SharingGroupServer']);
        }

        $result = $this->paginate();

        // check if the current user can modify or delete the SG
        $userOrganisationUuid = $this->Auth->user()['Organisation']['uuid'];
        foreach ($result as $k => $sg) {
            $editable = false;
            $deletable = false;

            if ($this->userRole['perm_site_admin'] || ($this->userRole['perm_sharing_group'] && $sg['Organisation']['uuid'] === $userOrganisationUuid)) {
                $editable = true;
                $deletable = true;
            } else if ($this->userRole['perm_sharing_group']) {
                if (!empty($sg['SharingGroupOrg'])) {
                    foreach ($sg['SharingGroupOrg'] as $sgo) {
                        if ($sgo['extend'] && $sgo['org_id'] == $this->Auth->user('org_id')) {
                            $editable = true;
                            break;
                        }
                    }
                }
            }

            $result[$k]['editable'] = $editable;
            $result[$k]['deletable'] = $deletable;
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(['response' => $result], $this->response->type()); // 'response' to keep BC
        }
        $this->set('passive', $passive);
        $this->set('sharingGroups', $result);
        $this->set('passedArgs', $passive ? 'true' : '[]');
        $this->set('title_for_layout', __('Sharing Groups'));
    }

    public function view($id)
    {
        if ($this->request->is('head')) { // Just check if sharing group exists and user can access it
            $exists = $this->SharingGroup->checkIfAuthorised($this->Auth->user(), $id);
            return new CakeResponse(['status' => $exists ? 200 : 404]);
        }
        if (!$this->SharingGroup->checkIfAuthorised($this->Auth->user(), $id)) {
            throw new MethodNotAllowedException('Sharing group doesn\'t exist or you do not have permission to access it.');
        }

        $contain = array(
            'Organisation',
            'SharingGroupOrg' => array(
                'Organisation' => array(
                    'fields' => array('id', 'name', 'uuid', 'local')
                )
            ),
            'SharingGroupServer' => array(
                'Server' => array(
                    'fields' => array('id', 'name', 'url')
                )
            )
        );

        if (!$this->__showOrgs()) {
            unset($contain['SharingGroupOrg']);
            unset($contain['SharingGroupServer']);
            $this->SharingGroup->addCountField('org_count', $this->SharingGroup->SharingGroupOrg, ['SharingGroupOrg.sharing_group_id = SharingGroup.id']);
        }

        $sg = $this->SharingGroup->find('first', [
            'conditions' => Validation::uuid($id) ? ['SharingGroup.uuid' => $id] : ['SharingGroup.id' => $id],
            'contain' => $contain,
        ]);
        if (isset($sg['SharingGroupServer'])) {
            foreach ($sg['SharingGroupServer'] as $key => $sgs) {
                if ($sgs['server_id'] == 0) {
                    $sg['SharingGroupServer'][$key]['Server'] = array(
                        'id' => "0",
                        'name' => 'Local instance',
                        'url' => empty(Configure::read('MISP.external_baseurl')) ? Configure::read('MISP.baseurl') : Configure::read('MISP.external_baseurl')
                    );
                }
            }
        }
        if ($sg['SharingGroup']['sync_user_id']) {
            $this->loadModel('User');
            $syncUser = $this->User->find('first', array(
                'conditions' => array('User.id' => $sg['SharingGroup']['sync_user_id']),
                'recursive' => -1,
                'fields' => array('User.id'),
                'contain' => array('Organisation' => array(
                    'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'),
                ))
            ));
            if (empty($syncUser)) {
                $sg['SharingGroup']['sync_org_name'] = 'N/A';
            } else {
                $sg['SharingGroup']['sync_org_name'] = $syncUser['Organisation']['name'];
                $sg['SharingGroup']['sync_org'] = $syncUser['Organisation'];
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($sg, $this->response->type());
        }

        $this->loadModel('Event');
        $conditions = $this->Event->createEventConditions($this->Auth->user());
        $conditions['AND']['sharing_group_id'] = $sg['SharingGroup']['id'];
        $sg['SharingGroup']['event_count'] = $this->Event->find('count', [
            'conditions' => $conditions,
            'recursive' => -1,
            'callbacks' => false,
        ]);

        $this->set('mayModify', $this->SharingGroup->checkIfAuthorisedExtend($this->Auth->user(), $sg['SharingGroup']['id']));
        $this->set('id', $sg['SharingGroup']['id']);
        $this->set('sg', $sg);
        $this->set('title_for_layout', __('Sharing Group %s', $sg['SharingGroup']['name']));
    }

    private function __initialiseSGQuickEdit($id, $request)
    {
        if (!$this->request->is('post') || !$this->_isRest()) {
            //throw new MethodNotAllowedException('This action only accepts POST requests coming from the API.');
        }
        // allow passing the sg_id via a JSON object
        if (!$id) {
            $validParams = array('sg_id', 'sg_uuid', 'id', 'uuid');
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
        $sg = $this->SharingGroup->fetchSG($id, $this->Auth->user(), false);
        if (empty($sg)) {
            throw new MethodNotAllowedException('Invalid sharing group or no editing rights.');
        }
        return $sg;
    }

    private function __initialiseSGQuickEditObject($id, $request, $type = 'org')
    {
        $params = array(
            'org' => array(
                'org_id', 'org_uuid', 'org_name'
            ),
            'server' => array(
                'server_id', 'server_url', 'server_baseurl', 'server_name'
            )
        );
        if (!empty($id)) {
            if ($type == 'org') {
                return $this->SharingGroup->SharingGroupOrg->Organisation->fetchOrg($id);
            } else {
                return $this->SharingGroup->SharingGroupServer->Server->fetchServer($id);
            }
        }
        if ($type !== 'org' && $type !== 'server') {
            return false;
        }
        foreach ($params[$type] as $param) {
            if (!empty($request[$param])) {
                if ($type == 'org') {
                    return $this->SharingGroup->SharingGroupOrg->Organisation->fetchOrg($request[$param]);
                } else {
                    return $this->SharingGroup->SharingGroupServer->Server->fetchServer($request[$param]);
                }
            }
        }
    }

    public function addOrg($sg_id = false, $object_id = false, $extend = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->data);
        $org = $this->__initialiseSGQuickEditObject($object_id, $this->request->data, $type = 'org');
        if (empty($org)) {
            throw new MethodNotAllowedException('Invalid organisation.');
        }
        if (isset($this->request->data['extend'])) {
            $extend = $this->request->data['extend'];
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
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Organisation is already in the sharing group.', $this->response->type());
        }
        $this->SharingGroup->SharingGroupOrg->create();
        $sgo = array(
            'SharingGroupOrg' => array(
                'org_id' => $org['id'],
                'sharing_group_id' => $sg['SharingGroup']['id'],
                'extend' => $extend ? 1:0
            )
        );
        $result = $this->SharingGroup->SharingGroupOrg->save($sgo);
        return $this->__sendQuickSaveResponse($this->action, $result, 'Organisation');
    }

    public function removeOrg($sg_id = false, $object_id = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->data);
        $org = $this->__initialiseSGQuickEditObject($object_id, $this->request->data, $type = 'org');
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
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Organisation is not in the sharing group.', $this->response->type());
        }
        $result = $this->SharingGroup->SharingGroupOrg->delete($removeOrg);
        return $this->__sendQuickSaveResponse($this->action, $result, 'Organisation');
    }

    public function addServer($sg_id = false, $object_id = false, $all = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->data);
        $server = $this->__initialiseSGQuickEditObject($object_id, $this->request->data, $type = 'server');
        if (empty($server)) {
            throw new MethodNotAllowedException('Invalid Server.');
        }
        if (isset($this->request->data['all'])) {
            $all = $this->request->data['all'];
        }
        if (isset($this->request->data['all_orgs'])) {
            $all = $this->request->data['all_orgs'];
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
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Server is already in the sharing group.', $this->response->type());
        }
        $this->SharingGroup->SharingGroupServer->create();
        $sgs = array(
            'SharingGroupServer' => array(
                'server_id' => $server['Server']['id'],
                'sharing_group_id' => $sg['SharingGroup']['id'],
                'all_orgs' => $all ? 1:0
            )
        );
        $result = $this->SharingGroup->SharingGroupServer->save($sgs);
        return $this->__sendQuickSaveResponse($this->action, $result);
    }

    public function removeServer($sg_id = false, $object_id = false)
    {
        $sg = $this->__initialiseSGQuickEdit($sg_id, $this->request->data);
        $server = $this->__initialiseSGQuickEditObject($object_id, $this->request->data, $type = 'server');
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
            return $this->RestResponse->saveFailResponse('SharingGroup', $this->action, false, 'Server is not in the sharing group.', $this->response->type());
        }
        $result = $this->SharingGroup->SharingGroupServer->delete($removeServer);
        return $this->__sendQuickSaveResponse($this->action, $result);
    }

    private function __sendQuickSaveResponse($action, $result, $object_type = 'Server')
    {
        $actionType = 'added to';
        if (strpos($action, 'remove') !== false) {
            $actionType = 'removed from';
        }
        if ($result) {
            return $this->RestResponse->saveSuccessResponse('SharingGroup', $action, false, $this->response->type(), $object_type . ' ' . $actionType . ' the sharing group.');
        } else {
            return $this->RestResponse->saveFailResponse('SharingGroup', $action, false, $object_type . ' could not be ' . $actionType . ' the sharing group.', $this->response->type());
        }
    }

    /**
     * @return bool
     */
    private function __showOrgs()
    {
        return $this->Auth->user()['Role']['perm_sharing_group'] || !Configure::read('Security.hide_organisations_in_sharing_groups');
    }
}
