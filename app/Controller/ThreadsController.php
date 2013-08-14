<?php

App::uses('AppController', 'Controller');

/**
 * Thread Controller
 *
 */
class ThreadsController extends AppController {

	public $components = array(
		'Security',
		'Session',
	);
	
	public $paginate = array(
			'limit' => 60,
	);

	public function beforeFilter() {
		parent::beforeFilter();
	}
	
	
	public function view($thread_id = null) {
		if ($thread_id != null) {
			$this->Thread->id = $thread_id;
			if (!$this->Thread->exists()) {
				throw new NotFoundException(__('Invalid thread'));
			}			
			$params = array('conditions' => array('id' => $thread_id),
					'contain' => array(
							'Post' => array(
									'User',
							),
					)
			);
			$thread = $this->Thread->find('first', $params);
			$this->set('thread_id', $thread_id);
			$this->set('posts', $thread['Post']);
			$this->set('myuserid', $this->Auth->user('id'));
			$this->set('context', 'threads');
			$this->set('thread_title', $thread['Thread']['title']);
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
