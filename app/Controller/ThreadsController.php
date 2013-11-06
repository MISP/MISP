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
	
	
	public function view($thread_id) {		
		$this->Thread->recursive = -1;
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
		if (!$this->_isSiteAdmin()) {
			foreach ($posts as &$post) {
				if ($post['User']['org'] != $this->Auth->user('org')) {
					$post['User']['email'] = 'User ' . $post['User']['id'] . ' (' . $post['User']['org'] . ')';
				}
			}
		}
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
		$this->loadModel('Posts');
		$conditions = null;
			$conditions['AND']['OR'] = array(
					'Thread.distribution >' => 0, 
					'Thread.org' => $this->Auth->user('org'),
			);
			$conditions['AND'][] = array('Thread.post_count >' => 0);
			$this->paginate = array(
					'conditions' => array($conditions),
					'fields' => array('date_modified', 'date_created', 'org', 'distribution', 'title', 'post_count'),
					'contain' => array(
							'Post' =>array(
								'fields' => array(),
								'limit' => 1,
								'order' => 'Post.date_modified DESC',
								'User' => array(
									'fields' => array('id','email', 'org'),
									)
								),
							),
					'order' => array('Thread.date_modified' => 'desc'),
					'recursive' => 1
			);
		$threadsBeforeEmailRemoval = $this->paginate();
		if (!$this->_isSiteAdmin()) {
			foreach ($threadsBeforeEmailRemoval as &$thread) {
				if ($thread['Post'][0]['User']['org'] != $this->Auth->user('org')) $thread['Post'][0]['User']['email'] = 'User ' . $thread['Post'][0]['User']['id'] . " (" . $thread['Post'][0]['User']['org'] . ")";
			}
		}
		$this->set('threads', $threadsBeforeEmailRemoval);
		$this->loadModel('Event');
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}
}
?>
