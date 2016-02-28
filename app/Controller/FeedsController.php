<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

/**
 * Feedss Controller
 */
class FeedsController extends AppController {

	public $components = array('Security' ,'RequestHandler');	// XXX ACL component

	public $paginate = array(
			'limit' => 60,
			'recursive' => -1,
			'contain' => array(
			),
			'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
			'order' => array(
					'Feed.url' => 'ASC'
			),
	);

	public $uses = array('Feed');

	public function beforeFilter() {
		parent::beforeFilter();
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException('You don\'t have the required privileges to do that.');
	}

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->set('feeds', $this->paginate());
	}
	
	public function view($feedId) {
		$feed = $this->Feed->find('first', array('conditions' => array('Feed.id' => $feedId)));
	}
	
	public function toggleEnabled($feedId) {
		
	}
	
	public function add() {
		if ($this->request->is('post')) {
			if (isset($this->request->data['Feed']['pull_rules'])) $this->request->data['Feed']['rules'] = $this->request->data['Feed']['pull_rules'];
			$result = $this->Feed->save($this->request->data);
			if ($result) {
				$this->Session->setFlash('Feed added.');
				$this->redirect(array('controller' => 'feeds', 'action' => 'index'));
			}
			else $this->Session->setFlash('Feed could not be added.');
		} else {
			
		}
	}
	
	public function edit($feedId) {
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		$this->Feed->read();
		if ($this->request->is('post') || $this->request->is('put')) {
			
		} else {
			$this->request->data = $this->Feed->data;
		}
	}
	
	public function delete($feedId) {
		
	}
	
	public function fetchFromFeed($feedId) {
		
	}
}
