<?php

App::uses('AppController', 'Controller');

/**
 * Roles Controller
 *
 * @property Role $Role
 */
class RolesController extends AppController {

	public $options = array('0' => 'Read Only', '1' => 'Manage My Own Events', '2' => 'Manage Organization Events', '3' => 'Manage & Publish Organization Events'); // FIXME move this to Role Model

	public $components = array(
		'Security',
		'Session',
		'RequestHandler'
	);

	public $helpers = array('Js' => array('Jquery'));

	public $paginate = array(
			'limit' => 60,
			'order' => array(
					'Role.name' => 'ASC'
			)
	);

	public function view($id = null) {
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		if ($this->_isRest()) {
			return $this->RestResponse->viewData($this->Role->read(null, $id), $this->response->type());
		} else {
			$this->set('premissionLevelName', $this->Role->premissionLevelName);
			$this->set('role', $this->Role->read(null, $id));
			$this->set('id', $id);
		}
	}

	public function admin_add() {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		if ($this->request->is('post')) {
			$this->Role->create();
			if ($this->Role->save($this->request->data)) {
				if ($this->_isRest()) {
					$role = $this->Role->find('first', array(
						'recursive' => -1,
						'conditions' => array('Role.id' => $this->Role->id)
					));
					return $this->RestResponse->viewData($role, $this->response->type());
				} else {
					$this->Session->setFlash('The Role has been saved');
					$this->redirect(array('action' => 'index'));
				}
			} else {
				if ($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Role', 'admin_add', false, $this->Role->validationErrors, $this->response->type());
				} else {
					if (!($this->Session->check('Message.flash'))) {
						$this->Role->Session->setFlash(__(sprintf('The Role could not be saved. Please, try again.')));
					}
				}
			}
		} else if ($this->_isRest()) {
			return $this->RestResponse->describe('Roles', 'admin_add', false, $this->response->type());
		}
		$this->set('permFlags', $this->Role->permFlags);
		$this->set('options', $this->options);
	}

	public function admin_edit($id = null) {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		$this->Role->id = $id;
		if (!$this->Role->exists() && !$this->request->is('get')) {
			throw new NotFoundException('Invalid Role');
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
					$this->Session->setFlash('The Role has been saved');
					$this->redirect(array('action' => 'index'));
				}
			} else {
				if ($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Role', 'admin_edit', false, $this->Role->validationErrors, $this->response->type());
				} else {
					if (!($this->Session->check('Message.flash'))) {
						$this->Role->Session->setFlash(__(sprintf('The Role could not be saved. Please, try again.')));
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
		$this->set('options', $this->options);
		$this->set('permFlags', $this->Role->permFlags);
		$this->set('id', $id);
	}

	public function admin_index() {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'roles', 'action' => 'index', 'admin' => false));
		$this->recursive = 0;
		if ($this->_isRest()) {
			$roles = $this->Role->find('all', array(
				'recursive' => -1
			));
			return $this->RestResponse->viewData($roles, $this->response->type());
		} else {
			$this->set('list', $this->paginate());
			$this->set('permFlags', $this->Role->permFlags);
			$this->loadModel('AdminSetting');
			$this->set('default_role_id', $this->AdminSetting->getSetting('default_role'));
			$this->set('options', $this->options);
		}
	}

	public function admin_delete($id = null) {
		if (!$this->request->is('post') && !$this->request->is('put') && !$this->request->is('delete')) {
			throw new MethodNotAllowedException();
		}
		$this->Role->id = $id;
		if (!$this->Role->exists()) {
			throw new NotFoundException('Invalid Role');
		}
		if ($this->Role->delete()) {
			if ($this->_isRest()) {
				return $this->RestResponse->saveSuccessResponse('Roles', 'admin_delete', $id, $this->response->type());
			} else {
				$this->Session->setFlash(__('Role deleted'));
				$this->redirect(array('action' => 'index'));
			}
		}
		if ($this->_isRest()) {
			return $this->RestResponse->saveFailResponse('Roles', 'admin_delete', $id, $this->Role->validationErrors, $this->response->type());
		} else {
			$this->Session->setFlash('Role could not be deleted');
			$this->redirect(array('action' => 'index'));
		}
	}

	public function index() {
		$this->recursive = 0;
		if ($this->_isRest()) {
			$roles = $this->Role->find('all', array(
				'recursive' => -1
			));
			return $this->RestResponse->viewData($roles, $this->response->type());
		} else {
			$this->set('list', $this->paginate());
			$this->set('permFlags', $this->Role->permFlags);
			$this->loadModel('AdminSetting');
			$this->set('default_role_id', $this->AdminSetting->getSetting('default_role'));
			$this->set('options', $this->options);
		}
	}

	public function admin_set_default($role_id = false) {
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
			$message = $role_id ? 'Default role set.' : 'Default role unset.';
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
	}
}
