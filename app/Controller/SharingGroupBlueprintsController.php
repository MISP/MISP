<?php
App::uses('AppController', 'Controller');

class SharingGroupBlueprintsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index()
    {
        $params = [
            'filters' => ['name', 'uuid'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'globalActions', 'menuItem' => 'indexMG'));
    }

    public function add()
    {
        $currentUser = $this->Auth->user();
        $params = [
            'beforeSave' => function($data) use ($currentUser) {
                $data['SharingGroupBlueprint']['uuid'] = CakeText::uuid();
                $data['SharingGroupBlueprint']['user_id'] = $currentUser['id'];
                $data['SharingGroupBlueprint']['org_id'] = $currentUser['org_id'];
                return $data;
            }
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'globalActions', 'menuItem' => 'addMG'));
    }

    public function edit($id)
    {
        $this->set('menuData', array('menuList' => 'globalActions', 'menuItem' => 'editMG'));
        $this->set('id', $id);
        $params = [
            'fields' => ['rules', 'name']
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'view_cerebrate']);
        $this->CRUD->view($id, ['contain' => ['Organisation.name', 'Organisation.uuid', 'Organisation.id', 'SharingGroup.id', 'SharingGroup.name']]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', array('menuList' => 'globalActions', 'menuItem' => 'viewMG'));
    }

    public function viewOrgs($id)
    {
        $conditions = ['SharingGroupBlueprint.id' => $id];
        if (!$this->_isSiteAdmin()) {
            $conditions['SharingGroupBlueprint.org_id'] = $this->Auth->user('org_id');
        }
        $sharingGroupBlueprint = $this->SharingGroupBlueprint->find('first', ['conditions' => $conditions]);
        if (empty($sharingGroupBlueprint)) {
            throw new NotFoundException(__('Invalid Sharing Group Blueprint'));
        }
        // we create a fake user to restrict the visible sharing groups to the creator of the SharingGroupBlueprint, in case an admin wants to update it
        $fake_user = [
            'Role' => [
                'perm_site_admin' => false
            ],
            'org_id' => $sharingGroupBlueprint['SharingGroupBlueprint']['org_id'],
            'id' => 1
        ];
        $temp = $this->SharingGroupBlueprint->evaluateSharingGroupBlueprint($sharingGroupBlueprint, $fake_user);
        $orgs = $this->SharingGroupBlueprint->SharingGroup->Organisation->find('all', [
            'recursive' => -1,
            'fields' => ['id', 'uuid', 'name', 'sector', 'type', 'nationality'],
            'conditions' => ['id' => $temp['orgs']]
        ]);
        $this->set('data', $orgs);
        $this->set('menuData', array('menuList' => 'SharingGroupBlueprints', 'menuItem' => 'viewOrgs'));
    }

    public function execute($id = false)
    {
        $conditions = [];
        if (!empty($id)) {
            $conditions['SharingGroupBlueprint.id'] = $id;
        }
        if (!$this->Auth->user('Role')['perm_admin']) {
            $conditions['SharingGroupBlueprint.org_id'] = $this->Auth->user('org_id');
        }
        $sharingGroupBlueprints = $this->SharingGroupBlueprint->find('all', ['conditions' => $conditions, 'recursive' => 0]);
        if (empty($sharingGroupBlueprints)) {
            throw new NotFoundException(__('No valid blueprints found.'));
        }
        if ($this->request->is('post')) {
            $stats = $this->SharingGroupBlueprint->execute($sharingGroupBlueprints);
            $message = __(
                'Done, %s sharing group blueprint(s) matched. Sharing group changes: Created: %s. Updated: %s. Failed to create: %s.',
                count($sharingGroupBlueprints),
                $stats['created'],
                $stats['changed'],
                $stats['failed']
            );
            if ($this->IndexFilter->isRest()) {
                if ($stats['changed'] || $stats['created']) {
                    return $this->RestResponse->saveSuccessResponse('sharingGroupBlueprints', 'execute', $id, false, $message);
                } else {
                    return $this->RestResponse->saveFailResponse('sharingGroupBlueprints', 'execute', $id, $message, $this->response->type());
                }
            } else {
                $status = 'success';
                if ($stats['failed']) {
                    $status = 'error';
                    if ($stats['created'] || $stats['changed']) {
                        $status = 'info';
                    }
                }
                $this->Flash->{$status}($message);
                $this->redirect($this->referer());
            }
        } else {
           $this->set('id', empty($id) ? $id : 'all');
           $this->set('title', __('Execute Sharing Group Blueprint'));
           $this->set('question', __('Are you sure you want to (re)create a sharing group based on the Sharing Group Blueprint?'));
           $this->set('actionName', __('Execute'));
           $this->layout = false;
           $this->render('/genericTemplates/confirm');
        }
    }

    public function detach($id)
    {
        $conditions = [];
        if (empty($id)) {
            throw new MethodNotAllowedException(__('No ID specified.'));
        }
        $conditions['SharingGroupBlueprint.id'] = $id;
        if (!$this->Auth->user('Role')['perm_admin']) {
            $conditions['SharingGroupBlueprint.org_id'] = $this->Auth->user('org_id');
        }
        $sharingGroupBlueprint = $this->SharingGroupBlueprint->find('first', ['conditions' => $conditions, 'recursive' => -1]);
        if (empty($sharingGroupBlueprint)) {
            throw new NotFoundException(__('Invalid Sharing Group Blueprint'));
        }
        if ($this->request->is('post')) {
            $sharingGroupBlueprint['SharingGroupBlueprint']['sharing_group_id'] = 0;
            $result = $this->SharingGroupBlueprint->save($sharingGroupBlueprint);
            $message = $result ? __('Sharing group detached.') : __('Could not detach sharing group.');
            if ($this->IndexFilter->isRest()) {
                if ($result) {
                    return $this->RestResponse->saveSuccessResponse('sharingGroupBlueprints', 'detach', $id, false, $message);
                } else {
                    return $this->RestResponse->saveFailResponse('sharingGroupBlueprints', 'detach', $id, $message, $this->response->type());
                }
            } else {
                $this->Flash->{$result ? 'success' : 'error'}($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('id', $id);
            $this->set('title', __('Detach Sharing Group Blueprint'));
            $this->set('question', __('Are you sure you want to detach the associated sharing group from this Sharing Group Blueprint? This action is irreversible.'));
            $this->set('actionName', __('Detach'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }

    public function generateUuidList($id)
    {
        $orgs = $this->__getUuidList($id);
        return $this->RestResponse->viewData($orgs, 'json');
    }

    private function __getUuidList($id)
    {
        $conditions = [];
        if (empty($id)) {
            throw new MethodNotAllowedException(__('No ID specified.'));
        }
        $conditions['SharingGroupBlueprint.id'] = $id;
        if (!$this->Auth->user('Role')['perm_admin']) {
            $conditions['SharingGroupBlueprint.org_id'] = $this->Auth->user('org_id');
        }
        $sharingGroupBlueprint = $this->SharingGroupBlueprint->find('first', ['conditions' => $conditions, 'recursive' => -1]);
        if (empty($sharingGroupBlueprint)) {
            throw new NotFoundException(__('Invalid Sharing Group Blueprint'));
        }
        // we create a fake user to restrict the visible sharing groups to the creator of the SharingGroupBlueprint, in case an admin wants to update it
        $fake_user = [
            'Role' => [
                'perm_site_admin' => false
            ],
            'org_id' => $sharingGroupBlueprint['SharingGroupBlueprint']['org_id'],
            'id' => 1
        ];
        $temp = $this->SharingGroupBlueprint->evaluateSharingGroupBlueprint($sharingGroupBlueprint, $fake_user);
        $orgs = $this->SharingGroupBlueprint->SharingGroup->Organisation->find('list', [
            'recursive' => -1,
            'fields' => ['uuid'],
            'conditions' => ['id' => $temp['orgs']]
        ]);
        return array_values($orgs);
    }

    public function encodeSyncRule($id)
    {
        $org_uuids = $this->__getUuidList($id);
        $this->loadModel('Server');
        if ($this->request->is('post')) {
            if (!isset($this->request->data['SharingGroupBlueprint'])) {
                $this->request->data = ['SharingGroupBlueprint' => $this->request->data];
            }
            $server = $this->Server->find('first', [
                'conditions' => ['Server.id' => $this->request->data['SharingGroupBlueprint']['server_id']],
                'recursive' => -1
            ]);
            if (empty($server)) {
                throw new NotFoundException(__('Invalid server.'));
            }
            $server['Server']['pull_rules'] = json_decode($server['Server']['pull_rules'], true);
            $server['Server']['push_rules'] = json_decode($server['Server']['push_rules'], true);
            $rules = [];
            $type_to_update = empty($this->request->data['SharingGroupBlueprint']['type']) ? 'pull' : $this->request->data['SharingGroupBlueprint']['type'];
            $rule_to_update = empty($this->request->data['SharingGroupBlueprint']['rule']) ? 'OR' : $this->request->data['SharingGroupBlueprint']['rule'];
            $rules[$type_to_update][$rule_to_update] = $org_uuids;
            $server['Server'][$type_to_update . '_rules']['orgs'][$rule_to_update] = $rules[$type_to_update][$rule_to_update];
            $server['Server']['pull_rules'] = json_encode($server['Server']['pull_rules']);
            $server['Server']['push_rules'] = json_encode($server['Server']['push_rules']);
            if (!$this->Server->save($server)) {
                throw new InvalidArgumentException(__('Could not update the server - something went wrong.'));
            } else {
                if ($this->_isRest()) {
                    $server = $this->Server->find('first', [
                        'recursive' => -1,
                        'conditions' => ['Server.id' => $this->request->data['SharingGroupBlueprint']['server_id']]
                    ]);
                    return $this->RestResponse->viewData($server, 'json');
                } else {
                    $this->Flash->success(__('Server %s\'s %s rules\' %s branch updated with the blueprint\'s rules.', $server['Server']['id'], $type_to_update, $rule_to_update));
                    $this->redirect('/servers/index');
                }
            }
        }
        $servers = $this->Server->find('all', ['recursive' => -1]);
        if (empty($servers)) {
            throw new NotFoundException(__('No valid servers found.'));
        }
        $server_data = [];
        foreach ($servers as $s) {
            $server_data[$s['Server']['id']] = $s['Server']['name'];
        }
        $this->set('servers', $server_data);
    }
}
