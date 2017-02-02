<?php

App::uses('AppController', 'Controller');

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

	public function viewEvent($id) {
		$this->loadModel('Event');
		$result = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
		$thread_id = false;
		if ($result) {
			$thread_id = $this->Thread->find('first', array('recursive' => -1, 'conditions' => array('Thread.event_id' => $id), 'fields' => array('Thread.id')));
				if ($thread_id) {
					$thread_id = $thread_id['Thread']['id'];
				} else {
					if ($this->_isRest()) {
						return $this->RestResponse->viewData($array(), $this->response->type());
					}
					$thread_id = false;
				}
		}
		if ($thread_id) {
			$post_id = false;
			if (isset($this->passedArgs['post_id'])) $post_id = $this->passedArgs['post_id'];
			$response = $this->__view($thread_id, false, $post_id);
			if ($this->_isRest()) {
				return $response;
			}
		} else {
			throw new NotFoundException('Invalid Thread.');
		}
	}

	public function view($thread_id, $eventView = false) {
		$post_id = false;
		if (isset($this->passedArgs['post_id'])) $post_id = $this->passedArgs['post_id'];
		$response = $this->__view($thread_id, $eventView, $post_id);
		if ($this->_isRest()) {
			return $response;
		}
	}

	private function __view($thread_id, $eventView, $post_id) {
		if ($eventView) {
			$id = $thread_id;
			// Show the discussion
			$this->Thread->Behaviors->unload('SysLogLogable.SysLogLogable');
			$params = array('conditions' => array('event_id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'event_id', 'distribution', 'title', 'sharing_group_id', 'org_id')
			);
			$thread = $this->Thread->find('first', $params);
			if (!empty($thread)) {
				if (!$this->_isSiteAdmin()) {
					if ($thread['Thread']['distribution'] == 0 && $thread['Thread']['org_id'] != $this->Auth->user('org_id')) {
						throw new MethodNotAllowedException('Invalid Thread.');
					}
					if ($thread['Thread']['distribution'] == 4) {
						if (!$this->Thread->SharingGroup->checkIfAuthorised($this->Auth->user(), $thread['Thread']['sharing_group_id'])) new NotFoundException('Invalid thread.');
					}
				}
				$thread_id = $thread['Thread']['id'];
			} else $thread_id = 0;
			$this->set('currentEvent', $id);
		} else {
			$this->Thread->recursive = -1;
			$this->Thread->id = $thread_id;

			//If the thread doesn't exist, throw exception
			if (!$this->Thread->exists()) {
				throw new NotFoundException('Invalid thread.');
			}
			$thread = $this->Thread->read();

			// If the thread belongs to an event, we have to make sure that the event's distribution level hasn't changed.
			// This is also a good time to update the thread's distribution level if that did happen.
			if (!empty($thread['Thread']['event_id'])) {
				$this->loadModel('Event');
				$this->Event->id = $thread['Thread']['event_id'];
				$this->Event->recursive = -1;
				$this->Event->read(array('id', 'distribution', 'org_id', 'sharing_group_id'));
				if ($this->Event->data['Event']['distribution'] != $thread['Thread']['distribution']) {
					$this->Thread->saveField('distribution', $this->Event->data['Event']['distribution']);
				}
				if ($this->Event->data['Event']['sharing_group_id'] != $thread['Thread']['sharing_group_id']) {
					$this->Thread->saveField('sharing_group_id', $this->Event->data['Event']['sharing_group_id']);
				}
				$this->set('event_id', $thread['Thread']['event_id']);
			}

			// If the user shouldn't be allowed to see the event send him away.
			if (!$this->_isSiteAdmin()) {
				if ($thread['Thread']['distribution'] == 0 && $thread['Thread']['org_id'] != $this->Auth->user('org_id')) {
					throw new MethodNotAllowedException('Invalid Thread.');
				}
				if ($thread['Thread']['distribution'] == 4) {
					if (!$this->Thread->SharingGroup->checkIfAuthorised($this->Auth->user(), $thread['Thread']['sharing_group_id'])) new NotFoundException('Invalid thread.');
				}
			}
		}
		if ($thread_id) {
			$this->paginate = array(
					'limit' => 10,
					'conditions' => array('Post.thread_id' => $thread_id),
					'contain' => array(
							'User' => array(
									'fields' => array('User.email', 'User.id'),
									'Organisation' => array(
											'fields' => array('id', 'name')
									),
							),
					),
			);
			if ($this->_isRest()) {
				$posts = $this->Thread->Post->find('all', array(
					'contain' => $this->paginate['contain'],
					'conditions' => $this->paginate['conditions']
				));
			} else {
				$posts = $this->paginate('Post');
			}
			foreach ($posts as $k => $post) {
				if (!empty($post['User'])) {
					$posts[$k]['Post']['org_name'] = $post['User']['Organisation']['name'];
					if ($this->_isSiteAdmin() || $this->Auth->user('org_id') == $post['User']['org_id']) {
						$posts[$k]['Post']['user_email'] = $post['User']['email'];
					}
					$posts[$k]['Post']['user_id'] = $post['User']['id'];
					$posts[$k] = $posts[$k]['Post'];
				}
			}
			if ($this->_isRest()) {
				if (!empty($posts)) {
					$thread['Thread']['Post'] = $posts;
				}
				return $this->RestResponse->viewData($thread, $this->response->type());
			} else {
				$this->set('posts', $posts);
				$this->set('post_id', $post_id);
				$this->set('thread', $thread);
			}
		}
		if ($eventView) {
			$this->set('context', 'event');
			if (!$this->request->is('ajax')) {
				$this->redirect(array('controller' => 'events', 'action' => 'view', $id));
			}
		} else $this->set('context', 'thread');
		$this->set('myuserid', $this->Auth->user('id'));
		if ($this->request->is('ajax')) {
			$this->layout = 'ajax';
			$this->render('/Elements/eventdiscussion');
		}
	}

	public function index() {
		$this->loadModel('Posts');
		$this->loadModel('SharingGroup');
		$sgids = $this->SharingGroup->fetchAllAuthorised($this->Auth->user);
		$conditions = null;
		if (!$this->_isSiteAdmin()) {
			$conditions['AND']['OR'] = array(
				'Thread.distribution' => array(1, 2, 3),
				array(
					'AND' => array(
						'Thread.distribution' => 0,
						'Thread.org_id' => $this->Auth->user('org_id'),
					)
				),
				array(
					'AND' => array(
						'Thread.distribution' => 4,
						'Thread.sharing_group_id' => $sgids,
					)
				)
			);
		}
		$conditions['AND'][] = array('Thread.post_count >' => 0);
		$this->paginate = array(
				'conditions' => array($conditions),
				'fields' => array('date_modified', 'date_created', 'org_id', 'distribution', 'title', 'post_count', 'sharing_group_id'),
				'contain' => array(
					'Post' =>array(
						'fields' => array(),
						'limit' => 1,
						'order' => 'Post.date_modified DESC',
						'User' => array(
							'fields' => array('id','email', 'org_id'),
							'Organisation' => array(
								'fields' => array('id', 'name')
							),
						),
					),
					'Organisation' => array(
						'fields' => array('id', 'name')
					),
					'SharingGroup' => array(
						'fields' => array('id', 'name')
					),
				),
				'order' => array('Thread.date_modified' => 'desc'),
				'recursive' => -1
		);
		$threadsBeforeEmailRemoval = $this->paginate();
		if (!$this->_isSiteAdmin()) {
			foreach ($threadsBeforeEmailRemoval as $key => $thread) {
				if (empty($thread['Post'][0]['User']['org_id'])) $threadsBeforeEmailRemoval[$key]['Post'][0]['User']['email'] = 'Deactivated user';
				else if ($thread['Post'][0]['User']['org_id'] != $this->Auth->user('org_id')) $threadsBeforeEmailRemoval[$key]['Post'][0]['User']['email'] = 'User ' . $thread['Post'][0]['User']['id'] . " (" . $thread['Post'][0]['User']['Organisation']['name'] . ")";
			}
		}
		$this->set('threads', $threadsBeforeEmailRemoval);
		$this->loadModel('Event');
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}
}
?>
