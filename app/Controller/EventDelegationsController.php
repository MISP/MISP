<?php
App::uses('AppController', 'Controller');

class EventDelegationsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
				'EventDelegations.id' => 'DESC'
			),
	);

	public function index() {
	}

	public function add() {
		
	}
	
	public function edit($id) {
		
	}

	public function delete($id) {
		
	}

	public function delegateEvent($id) {
		debug($this->EventDelegation->find('all'));
		$event = $this->EventDelegation->Event->find('first', array(
				'conditions' => array('Event.id' => $id),
				'recursive' => -1,
				'fields' => array('Event.id', 'Event.orgc_id', 'Event.distribution')
		));
		if (!$this->_isSiteAdmin() || $this->Auth->user('org_id') !== $event['Event']['orgc_id']) throw new MethodNotAllowedException('You are not authorised to do that.');
		if ($event['Event']['distribution'] != 0) throw new MethodNotAllowedException('Only events with the distribution setting "Your Organisation Only" can be delegated.');
		if ($this->request->is('Post')) {
			
		} else {
			
		}
	}
	
}
