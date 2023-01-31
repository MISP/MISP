<?php

namespace App\Controller\Admin;

use App\Controller\AppController;
use Cake\Utility\Hash;
use Cake\Utility\Text;
use Cake\Database\Expression\QueryExpression;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\ForbiddenException;

class RolesController extends AppController
{

    public $filterFields = ['name', 'uuid', 'perm_admin', 'Users.id', 'perm_org_admin'];
    public $quickFilterFields = ['name'];
    public $containFields = [];

    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'Role.name' => 'ASC'
            )
    );

    public function add()
    {
        $rolesModel = $this->Roles;
        $this->CRUD->add([
            'afterSave' => function ($data) use ($rolesModel) {
                if ($data['is_default']) {
                    $rolesModel->query()->update()->set(['is_default' => false])->where(['id !=' => $data->id])->execute();
                }
                return true;
            }
        ]);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('permFlags', $this->Roles->permFlags());
        $this->set('metaGroup', $this->isAdmin ? 'Administration' : 'Cerebrate');
        $dropdownData = [
            'options' => $this->Roles->premissionLevelName,
        ];
        $this->set(compact('dropdownData'));
    }

    public function edit($id = null)
    {
        $this->Role->id = $id;
        if (!$this->Role->exists() && !$this->request->is('get')) {
            throw new NotFoundException(__('Invalid Role'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['Role'])) {
                $this->request->data = array('Role' => $this->request->data);
            }
            $this->request->data['Role']['id'] = $id;
            if ($this->Role->save($this->request->data)) {
                if ($this->_isRest()) {
                    $role = $this->Role->find('first', array(
                        'recursive' => -1,
                        'conditions' => array('Role.id' => $this->Role->id)
                    ));
                    return $this->RestResponse->viewData($role, $this->response->type());
                } else {
                    $this->Flash->success(__('The Role has been saved'));
                    $this->redirect(array('action' => 'index', 'admin' => false));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Role', 'admin_edit', false, $this->Role->validationErrors, $this->response->type());
                } else {
                    if (!($this->Session->check('Message.flash'))) {
                        $this->Role->Session->setFlash(__('The Role could not be saved. Please, try again.'));
                    }
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Roles', 'admin_edit', false, $this->response->type());
            }
            $this->request->data['Role']['id'] = $id;
            $this->request->data = $this->Role->read(null, $id);
        }
        $this->set('options', $this->Role->premissionLevelName);
        $this->set('permFlags', $this->Role->permFlags);
        $this->set('id', $id);
    }

    public function delete($id = null)
    {
        $this->CRUD->delete($id, [
            'validate' => function (array $role) {
                $usersWithRole = $this->User->find('count', [
                    'conditions' => ['role_id' => $role['Role']['id']],
                    'recursive' => -1,
                ]);
                if ($usersWithRole) {
                    throw new Exception(__("It is not possible to delete role that is assigned to users."));
                }
            }
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function index()
    {
        $this->CRUD->index([
            'filters' => $this->filterFields,
            'quickFilters' => $this->quickFilterFields
        ]);
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

    public function set_default($role_id = false)
    {
        if ($this->request->is('post')) {
            $this->Role->id = $role_id;
            if ((!is_numeric($role_id) && $role_id !== false) || !$this->Role->exists()) {
                $message = 'Invalid Role.';
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Roles', 'admin_set_default', $role_id, $message, $this->response->type());
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $message)), 'status'=>200, 'type' => 'json'));
                }
            }
            $this->loadModel('AdminSetting');
            $result = $this->AdminSetting->changeSetting('default_role', $role_id);
            if ($result === true) {
                $message = $role_id ? __('Default role set.') : __('Default role unset.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Roles', 'admin_set_default', $role_id, $this->response->type(), $message);
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message)), 'status'=>200, 'type' => 'json'));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Roles', 'admin_set_default', $role_id, $result, $this->response->type());
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $result)), 'status'=>200, 'type' => 'json'));
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->saveFailResponse('Role', 'admin_set_default', false, __('This endpoint expects a POST request.'), $this->response->type());
            } else {
                $this->layout = false;
            }
        }
    }
}
