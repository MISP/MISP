<?php
App::uses('AppController', 'Controller');
/**
 * Groups Controller
 *
 * @property Group $Group
 */
class GroupsController extends AppController {

	public $components = array(
        'Acl',
        'Auth' => array(
            'authorize' => array(
                'Actions' => array('actionPath' => 'controllers/Groups')
            )
        ),
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
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->Group->recursive = 0;
		$this->set('groups', $this->paginate());
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
			throw new NotFoundException(__('Invalid group'));
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
			if ($this->Group->save($this->request->data)) {
				$this->Session->setFlash(__('The group has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The group could not be saved. Please, try again.'));
			}
		} else {
			// generate auth key for a new user
			//$newkey = $this->Group->generateAuthKey();	// TODO generateAuthKey?
			//$this->set('authkey', $newkey);
		}
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
			throw new NotFoundException(__('Invalid group'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			$fields = array();
			foreach (array_keys($this->request->data['Group']) as $field) {
				if($field != 'password') array_push($fields, $field);
			}
			if ("" != $this->request->data['Group']['password'])
				$fields[] = 'password';
			if ($this->Group->save($this->request->data, true, $fields)) {
				$this->saveAcl($this->Group, $this->data['Group']['perm_add'], $this->data['Group']['perm_modify']);	// save to ACL as well
				$this->Session->setFlash(__('The group has been saved'));
				$this->_refreshAuth(); // in case we modify ourselves
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The group could not be saved. Please, try again.'));
			}
		} else {
			$this->Group->recursive=0;
			$this->Group->read(null, $id);
			//$this->Group->set('password', '');	// TODO set password?
			$this->request->data = $this->Group->data;

		}
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
		if ($this->Group->delete()) {
			$this->Session->setFlash(__('Group deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Group was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

/**
 * saveAcl method
 *
 * @param string $id
 * @return void
 */
	public function saveAcl($group, $permAdd = false, $permModify = false) {
		// this all could need some 'if-changed then do'
		
		// mandatory allowed controllers
		//$this->Acl->allow($group, 'controllers');
		
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
