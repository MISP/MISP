<?php

App::uses('AppController', 'Controller');

/**
 * Roles Controller
 *
 * @property Role $Role
 */
class RolesController extends AppController
{
    public $components = array(
        'Session',
        'RequestHandler'
    );

    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'Role.name' => 'ASC'
            )
    );

    public function view($id=false)
    {
        $this->CRUD->view($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('permissionLevelName', $this->Role->permissionLevelName);
        $this->set('permFlags', $this->Role->permFlags);
        $this->set('menuData', ['menuList' => 'globalActions', 'menuItem' => 'roles']);
    }

    public function admin_add()
    {
        $params = ['redirect' => ['action' => 'index', 'admin' => false]];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('permFlags', $this->Role->permFlags);
        $dropdownData = [
            'options' => $this->Role->permissionLevelName,
        ];
        $this->set(compact('dropdownData'));
        $this->set('menuData', array('menuList' => 'admin', 'menuItem' => 'addRole'));
        if ($this->theme === "Overmind") {
            $this->layout = false;
        }
    }

    public function admin_edit($id = null)
    {
        $params = [
            'redirect' => ['action' => 'index', 'admin' => false]
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('options', $this->Role->permissionLevelName);
        $this->set('permFlags', $this->Role->permFlags);
        $this->set('id', $id);
        if ($this->theme === "Overmind") {
            $this->layout = false;
            $this->render('admin_add');
        }
    }

    public function admin_delete($id = null)
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

    /**
     * Confirmation + handler for single-row and mass role deletion (Overmind).
     *
     * GET  (opened via openModal): renders the confirmation modal, splitting the
     *      selection into deletable roles and roles blocked by assigned users.
     * POST (from the modal form): deletes the roles with no users assigned and
     *      skips the rest, reporting a clear message.
     */
    public function admin_deleteSelection($id = null)
    {
        if ($this->request->is(['post', 'put', 'delete'])) {
            $idList = $this->request->data['Role']['id'] ?? $id;
            if (!is_array($idList)) {
                $idList = (is_numeric($idList)) ? [$idList] : json_decode($idList, true);
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }

            $deleted = 0;
            $failed = 0;
            $blocked = [];
            foreach ($idList as $roleId) {
                $role = $this->Role->find('first', [
                    'conditions' => ['Role.id' => $roleId],
                    'recursive' => -1,
                ]);
                if (empty($role)) {
                    $failed++;
                    continue;
                }
                $usersWithRole = $this->User->find('count', [
                    'conditions' => ['role_id' => $role['Role']['id']],
                    'recursive' => -1,
                ]);
                if ($usersWithRole) {
                    $blocked[] = $role['Role']['name'];
                    continue;
                }
                if ($this->Role->delete($role['Role']['id'])) {
                    $deleted++;
                } else {
                    $failed++;
                }
            }

            $messages = [];
            if ($deleted) {
                $messages[] = __n('%s role deleted.', '%s roles deleted.', $deleted, $deleted);
            }
            if (!empty($blocked)) {
                $messages[] = count($blocked) === 1
                    ? __('Role "%s" was not deleted because it is still assigned to users.', $blocked[0])
                    : __('%s roles were not deleted because they are still assigned to users: %s', count($blocked), implode(', ', $blocked));
            }
            if ($failed) {
                $messages[] = __n('%s role could not be deleted.', '%s roles could not be deleted.', $failed, $failed);
            }
            $message = trim(implode(' ', $messages));

            if ($this->IndexFilter->isRest()) {
                if ($deleted) {
                    return $this->RestResponse->saveSuccessResponse('Roles', 'admin_deleteSelection', $id, $this->response->type(), $message);
                }
                return $this->RestResponse->saveFailResponse('Roles', 'admin_deleteSelection', false, $message, $this->response->type());
            }

            if ($deleted && empty($blocked) && !$failed) {
                $this->Flash->success($message);
            } elseif ($deleted) {
                $this->Flash->warning($message);
            } else {
                $this->Flash->error($message ?: __('No roles were deleted.'));
            }
            return $this->redirect(['action' => 'index', 'admin' => false]);
        }

        // GET → build the confirmation modal.
        $idList = is_numeric($id) ? [$id] : json_decode($id, true);
        if (empty($idList)) {
            throw new NotFoundException(__('Invalid input.'));
        }
        $roles = $this->Role->find('all', [
            'conditions' => ['Role.id' => $idList],
            'recursive' => -1,
            'fields' => ['Role.id', 'Role.name'],
        ]);
        $deletable = [];
        $blocked = [];
        foreach ($roles as $role) {
            $count = $this->User->find('count', [
                'conditions' => ['role_id' => $role['Role']['id']],
                'recursive' => -1,
            ]);
            if ($count) {
                $blocked[] = ['name' => $role['Role']['name'], 'count' => $count];
            } else {
                $deletable[] = ['id' => $role['Role']['id'], 'name' => $role['Role']['name']];
            }
        }

        $this->request->data['Role']['id'] = json_encode($idList);
        $this->set('idArray', $idList);
        $this->set('deletable', $deletable);
        $this->set('blocked', $blocked);
        $this->layout = false;
        $this->render('/Roles/ajax/roleDeleteConfirmationForm');
    }

    /**
     * Grant/deny a single permission flag on a role (Overmind role view).
     *
     * GET  (opened via openModal): renders the toggle confirmation modal.
     * POST (from the modal form): flips the flag and saves the whole role so the
     *      permission-level-derived flags stay consistent (see Role::beforeSave).
     */
    public function admin_togglePermission($id = null, $perm = null)
    {
        $permFlags = $this->Role->permFlags;
        if (empty($perm) || !isset($permFlags[$perm])) {
            throw new NotFoundException(__('Invalid permission.'));
        }
        $role = $this->Role->find('first', [
            'conditions' => ['Role.id' => $id],
            'recursive' => -1,
        ]);
        if (empty($role)) {
            throw new NotFoundException(__('Invalid Role.'));
        }

        if ($this->request->is(['post', 'put'])) {
            $newValue = empty($role['Role'][$perm]) ? 1 : 0;
            $role['Role'][$perm] = $newValue;
            // Set the id explicitly so the `name` isUnique rule excludes this
            // very record when re-validating on save.
            $this->Role->id = $role['Role']['id'];
            $saved = $this->Role->save($role);
            $message = $saved
                ? __('Permission "%s" %s for role "%s".', $permFlags[$perm]['text'], $newValue ? __('granted') : __('denied'), $role['Role']['name'])
                : __('The permission could not be updated.');
            if ($this->IndexFilter->isRest()) {
                if ($saved) {
                    return $this->RestResponse->saveSuccessResponse('Roles', 'admin_togglePermission', $id, $this->response->type(), $message);
                }
                return $this->RestResponse->saveFailResponse('Roles', 'admin_togglePermission', $id, $message, $this->response->type());
            }
            if ($saved) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            return $this->redirect(['action' => 'view', $id, 'admin' => false]);
        }

        $this->set('role', $role['Role']);
        $this->set('perm', $perm);
        $this->set('permFlag', $permFlags[$perm]);
        $this->set('granted', !empty($role['Role'][$perm]));
        $this->layout = false;
        $this->render('/Roles/ajax/rolePermissionToggleForm');
    }

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
        $this->set('options', $this->Role->permissionLevelName);
        $this->set('permFlags', $this->Role->permFlags);
        $this->set('menuData', $this->_isAdmin() ?
            ['menuList' => 'admin', 'menuItem' => 'indexRole'] :
            ['menuList' => 'globalActions', 'menuItem' => 'roles']
        );
    }

    public function admin_set_default($role_id = false)
    {
        if ($this->request->is('post')) {
            $this->Role->id = $role_id;
            if ((!is_numeric($role_id) && $role_id !== false) || !$this->Role->exists()) {
                $message = 'Invalid Role.';
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Roles', 'admin_set_default', $role_id, $message, $this->response->type());
                } elseif ($this->theme === "Overmind") {
                    $this->Flash->error($message);
                    return $this->redirect(array('action' => 'index', 'admin' => false));
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
                } elseif ($this->theme === "Overmind") {
                    $this->Flash->success($message);
                    return $this->redirect(array('action' => 'index', 'admin' => false));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message)), 'status'=>200, 'type' => 'json'));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Roles', 'admin_set_default', $role_id, $result, $this->response->type());
                } elseif ($this->theme === "Overmind") {
                    $this->Flash->error($result);
                    return $this->redirect(array('action' => 'index', 'admin' => false));
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
