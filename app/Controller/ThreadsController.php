<?php

App::uses('AppController', 'Controller');

/**
 * Thread Controller
 *
 */
class ThreadsController extends AppController {

	public $components = array(
		'Security',
		'RequestHandler',
		'Session',
	);
	
	public $helpers = array('Js' => array('Jquery'));
	
	public $paginate = array(
			'limit' => 60,
	);

	public function beforeFilter() {
		parent::beforeFilter();
	}
	
	
	public function view($thread_id) {		$this->Thread->recursive = -1;
		$this->Thread->id = $thread_id;
		
		//If the thread doesn't exist, throw exception
		if (!$this->Thread->exists()) {
			throw new NotFoundException('Invalid thread.');
		}
		$this->Thread->read();
		
		// If the thread belongs to an event, we have to make sure that the event's distribution level hasn't changed.
		// This is also a good time to update the thread's distribution level if that did happen.
		if (!empty($this->Thread->data['Thread']['event_id'])) {
			$this->loadModel('Event');
			$this->Event->id = $this->Thread->data['Thread']['event_id'];
			$this->Event->recursive = -1;
			$this->Event->read(array('id', 'distribution', 'org'));
			if ($this->Event->data['Event']['distribution'] != $this->Thread->data['Thread']['distribution']) {
				$this->Thread->saveField('distribution', $this->Event->data['Event']['distribution']);
			}
		}
											
		// If the user shouldn't be allowed to see the event send him away.
		if (!$this->_isSiteAdmin() && $this->Thread->data['Thread']['distribution'] == 0 && $this->Thread->data['Thread']['org'] != $this->Auth->user('org')) {
			throw new MethodNotAllowedException('You are not authorised to view this.');
		}
			
		$this->paginate = array(
				'limit' => 10,
				'conditions' => array('Post.thread_id' => $thread_id),
				'contain' => 'User'
		);
		$posts = $this->paginate('Post');
		$this->set('posts', $posts);
		$this->set('thread_id', $thread_id);
		$this->set('myuserid', $this->Auth->user('id'));
		$this->set('thread_title', $this->Thread->data['Thread']['title']);
		if ($this->request->is('ajax')) {
			$this->layout = 'ajax';
			$this->render('/Elements/eventdiscussion');
		}
	}
	
	public function index() {
		$conditions = null;
		
		//if (!$this->_isSiteAdmin()) {
			$conditions['OR'] = array(
					'Thread.distribution >' => 0, 
					'Thread.org' => $this->Auth->user('org'),
			);
			//$conditions[] = array('Thread.event_id' => 0);
		//}
			$this->paginate = array(
					'conditions' => array($conditions),
					'fields' => array('date_modified', 'date_created', 'org', 'distribution', 'title', 'post_count'),
					'contain' => array(
							'Post' =>array(
								'fields' => array(),
								'User' => array(
									'fields' => array('email', 'org')
									)
								),
							),
					'order' => array('Thread.date_modified' => 'desc'),
					'recursive' => 1
			);
		$this->set('threads', $this->paginate());
		$this->loadModel('Event');
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}
}
?>
