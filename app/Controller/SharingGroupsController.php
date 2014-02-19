<?php
App::uses('AppController', 'Controller');

class SharingGroupsController extends AppController {

	public function admin_index() {
        $this->paginate = array('contain' => array('Organisation'));
		$this->set('sharingGroups', $this->paginate());
	}

	public function admin_add() {
		if ($this->request->is('post')) {
			$this->SharingGroup->create();
			if ($this->SharingGroup->save($this->request->data)) {
				$this->Session->setFlash(__('The sharing group has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The sharing group could not be saved. Please, try again.'));
			}
		}
	}

	public function admin_edit($id = null) {
		if (!$this->SharingGroup->exists($id)) {
			throw new NotFoundException(__('Invalid sharing group'));
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->SharingGroup->save($this->request->data)) {
				$this->Session->setFlash(__('The sharing group has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The sharing group could not be saved. Please, try again.'));
			}
		} else {
			$options = array('conditions' => array('SharingGroup.' . $this->SharingGroup->primaryKey => $id));
			$this->request->data = $this->SharingGroup->find('first', $options);
		}
	}

	public function admin_delete($id = null) {
		$this->SharingGroup->id = $id;
		if (!$this->SharingGroup->exists()) {
			throw new NotFoundException(__('Invalid sharing group'));
		}
		$this->request->onlyAllow('post', 'delete');
		if ($this->SharingGroup->delete()) {
			$this->Session->setFlash(__('Sharing group deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Sharing group was not deleted'));
		$this->redirect(array('action' => 'index'));
	}
}
