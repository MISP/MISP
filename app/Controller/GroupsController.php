<?php
App::uses('AppController', 'Controller');
/**
 * Groups Controller
 *
 * @property Group $Group
 */
class GroupsController extends AppController {

	public $options = array('0' => 'Read Only', '1' => 'Manage My Own Events', '2' => 'Manage Organization Events', '3' => 'Manage & Publish Organization Events');

	public $components = array(
        'Acl',
        'Auth' => array(
            'authorize' => array(
                'Actions' => array('actionPath' => 'controllers/Groups')
            )
        ),
        'Security',
        'Session'
    );

    //public $components = array('Security');
    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'Group.name' => 'ASC'
            )
    );

    function beforeFilter() {
        parent::beforeFilter();
    }

/**
 * view method
 *
 * @param string $id
 * @return void
 */
	public function view($id = null) {
		$this->Group->id = $id;
		if (!$this->Group->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		$this->set('group', $this->Group->read(null, $id));
	}

/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->Group->recursive = 0;
		$this->set('groups', $this->paginate());
		$this->set('options', $this->options);
	}

/**
 * admin_view method
 *
 * @param string $id
 * @return void
 */
	public function admin_view($id = null) {
		$this->Group->id = $id;
		if (!$this->Group->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		$this->set('group', $this->Group->read(null, $id));
	}

/**
 * admin_add method
 *
 * @return void
 */
	public function admin_add() {
		if ($this->request->is('post')) {
			$this->Group->create();
			$this->request->data = $this->Group->massageData(&$this->request->data);
			if ($this->Group->save($this->request->data)) {
				$this->saveAcl($this->Group, $this->data['Group']['perm_add'], $this->data['Group']['perm_modify'], $this->data['Group']['perm_publish']);	// save to ACL as well
				$this->Session->setFlash(__('The role has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The role could not be saved. Please, try again.'));
			}
		}
		$this->set('options', $this->options);
	}

/**
 * admin_edit method
 *
 * @param string $id
 * @return void
 */
	public function admin_edit($id = null) {
		$this->Group->id = $id;
		if (!$this->Group->exists()) {
			throw new NotFoundException(__('Invalid role'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			$fields = array();
			$this->request->data = $this->Group->massageData(&$this->request->data);
			if ($this->Group->save($this->request->data, true, $fields)) {
				$this->saveAcl($this->Group, $this->data['Group']['perm_add'], $this->data['Group']['perm_modify'], $this->data['Group']['perm_publish']);	// save to ACL as well
				$this->Session->setFlash(__('The role has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The role could not be saved. Please, try again.'));
			}
		} else {
			$this->Group->recursive=0;
			$this->Group->read(null, $id);
			$this->request->data = $this->Group->data;
		}
		$this->set('options', $this->options);
	}

/**
 * admin_delete method
 *
 * @param string $id
 * @return void
 */
	public function admin_delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Group->id = $id;
		if (!$this->Group->exists()) {
			throw new NotFoundException(__('Invalid group'));
		}
		if ($this->Group->delete(null, false)) {
			$this->Session->setFlash(__('Role deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Role was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

/**
 * saveAcl method
 *
 * @param string $id
 * @return void
 */
	public function saveAcl($group, $permAdd = false, $permModify = false, $permPublish = false) {
		// this all could need some 'if-changed then do'

		if ($permAdd) {
			$this->Acl->allow($group, 'controllers/Events/add');
			$this->Acl->allow($group, 'controllers/Attributes/add');
		} else {
			$this->Acl->deny($group, 'controllers/Events/add');
			$this->Acl->deny($group, 'controllers/Attributes/add');
		}
		if ($permModify) {
			$this->Acl->allow($group, 'controllers/Events/edit');
			$this->Acl->allow($group, 'controllers/Attributes/edit');
		} else {
			$this->Acl->deny($group, 'controllers/Events/edit');
			$this->Acl->deny($group, 'controllers/Attributes/edit');
		}
		if ($permPublish) {
			$this->Acl->allow($group, 'controllers/Events/publish');
		} else {
			$this->Acl->deny($group, 'controllers/Events/publish');
		}
	}
}
