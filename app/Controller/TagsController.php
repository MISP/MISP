<?php

App::uses('AppController', 'Controller');

/**
 * Tags Controller
 *
 * @property Tag $Tag
 */

class TagsController extends AppController {
	public $components = array('Security' ,'RequestHandler');

	public $paginate = array(
			'limit' => 50,
			'order' => array(
					'Tag.id' => 'desc'
			)
	);
	
	public $helpers = array('TextColour');
	
	public function beforeFilter() { // TODO REMOVE
		parent::beforeFilter();
	}
	
	public function index() {
		$this->set('list', $this->paginate());
		// send perm_tagger to view for action buttons
	}
	
	public function add() {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) {
			throw new NotFoundException('You don\'t have permission to do that.');
		}
		if ($this->request->is('post')) {
			if ($this->Tag->save($this->request->data)) {
				$this->Session->setFlash('The tag has been saved.');
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash('The tag could not be saved. Please, try again.');
			}
		}
	}
	
	public function edit($id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) {
			throw new NotFoundException('You don\'t have permission to do that.');
		}
		$this->Tag->id = $id;
		if (!$this->Tag->exists()) {
			throw new NotFoundException('Invalid tag');
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			if ($this->Tag->save($this->request->data)) {
				$this->Session->setFlash('The Tag has been edited');
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash('The Tag could not be saved. Please, try again.');
			}
		}
		$this->request->data = $this->Tag->read(null, $id);
	}
	
	public function delete($id) {
		if (!$this->_isSiteAdmin() && !$this->userRole['perm_tagger']) {
			throw new NotFoundException('You don\'t have permission to do that.');
		}
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Tag->id = $id;
		if (!$this->Tag->exists()) {
			throw new NotFoundException('Invalid tag');
		}
		if ($this->Tag->delete()) {
			$this->Session->setFlash(__('Attribute deleted'));
		} else {
			$this->Session->setFlash(__('Attribute was not deleted'));
		}
		$this->redirect(array('action' => 'index'));
	}
}