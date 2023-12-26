<?php

namespace App\Controller\Admin;

use App\Controller\AppController;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;
use Exception;

class RolesController extends AppController
{
    use LocatorAwareTrait;

    public $filterFields = ['name', 'uuid', 'perm_admin', 'Users.id', 'perm_org_admin'];
    public $quickFilterFields = ['name'];
    public $containFields = [];

    public $paginate = [
        'limit' => 60,
        'order' => [
            'Role.name' => 'ASC'
        ]
    ];

    public function add()
    {
        $rolesModel = $this->Roles;
        $this->CRUD->add(
            [
                'afterSave' => function ($data) use ($rolesModel) {
                    if ($data['is_default']) {
                        $rolesModel->query()->update()->set(['is_default' => false])->where(['id !=' => $data->id])->execute();
                    }
                    return true;
                }
            ]
        );
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('permFlags', $this->Roles->permFlags());
        $dropdownData = [
            'options' => $this->Roles->premissionLevelName,
        ];
        $this->set(compact('dropdownData'));
    }

    public function edit($id = null)
    {
        $this->CRUD->edit($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('permFlags', $this->Roles->permFlags());
        $dropdownData = [
            'options' => $this->Roles->premissionLevelName,
        ];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function delete($id = null)
    {
        $this->CRUD->delete(
            $id,
            [
                'validate' => function (array $role) {
                    $usersWithRole = $this->User->find(
                        'count',
                        [
                            'conditions' => ['role_id' => $role['Role']['id']],
                            'recursive' => -1,
                        ]
                    );
                    if ($usersWithRole) {
                        throw new Exception(__("It is not possible to delete role that is assigned to users."));
                    }
                }
            ]
        );
        if ($this->ParamHandler->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function index()
    {
        $this->CRUD->index(
            [
                'filters' => $this->filterFields,
                'quickFilters' => $this->quickFilterFields
            ]
        );
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('options', $this->Roles->premissionLevelName);
        $this->set('permFlags', $this->Roles->permFlags());
        $this->set('metaGroup', $this->isAdmin ? 'Administration' : 'Cerebrate');
    }
    /*
    public function index()
    {
        $params = [
            'filters' => ['name'],
            'quickFilters' => ['name'],
            'afterFind' => function($elements) {
                $this->loadModel('AdminSetting');
                $default_setting = $this->AdminSetting->getSetting('default_role');
                foreach ($elements as &$role) {
                    $role['Role']['default'] = $role['Role']['id'] == $default_setting;
                }
                return $elements;
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('options', $this->Role->premissionLevelName);
        $this->set('permFlags', $this->Role->permFlags);
        $this->set('menuData', $this->_isAdmin() ?
            ['menuList' => 'admin', 'menuItem' => 'indexRole'] :
            ['menuList' => 'globalActions', 'menuItem' => 'roles']
        );
    }
    */

    public function setDefault($role_id = false)
    {
        if ($this->request->is('post')) {
            $role = $this->Roles->get($role_id);
            if ((!is_numeric($role_id) && $role_id !== false) || !$role) {
                $message = 'Invalid Role.';
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Roles', 'admin_set_default', $role_id, $message, $this->response->getType());
                } else {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => $message]), 'status' => 200, 'type' => 'json']);
                }
            }
            $AdminSettingsTable = $this->fetchTable('AdminSettings');
            $result = $AdminSettingsTable->changeSetting('default_role', $role_id);
            if ($result === true) {
                $message = $role_id ? __('Default role set.') : __('Default role unset.');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Roles', 'admin_set_default', $role_id, $this->response->getType(), $message);
                } else {
                    return new Response(['body' => json_encode(['saved' => true, 'success' => $message]), 'status' => 200, 'type' => 'json']);
                }
            } else {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Roles', 'admin_set_default', $role_id, $result, $this->response->getType());
                } else {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => $result]), 'status' => 200, 'type' => 'json']);
                }
            }
        } else {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveFailResponse('Role', 'admin_set_default', false, __('This endpoint expects a POST request.'), $this->response->getType());
            } else {
                $this->layout = false;
            }
        }
    }
}
