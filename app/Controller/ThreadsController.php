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

	public function viewEvent($id) {
		$this->loadModel('Event');
		$result = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
		if (empty($result)) throw new MethodNotAllowedException('You are not authorised to see that.');
		$result = $result[0];
		// Show the discussion

		$this->Thread->Behaviors->unload('SysLogLogable.SysLogLogable');
		$params = array('conditions' => array('event_id' => $id),
				'recursive' => -1,
				'fields' => array('id', 'event_id', 'distribution', 'title', 'sharing_group_id')
		);
		$thread = $this->Thread->find('first', $params);
		if (empty($thread)) {
			$newThread = array(
					'date_created' => date('Y/m/d H:i:s'),
					'date_modified' => date('Y/m/d H:i:s'),
					'user_id' => $this->Auth->user('id'),
					'event_id' => $id,
					'title' => 'Discussion about Event #' . $result['Event']['id'] . ' (' . $result['Event']['info'] . ')',
					'distribution' => $result['Event']['distribution'],
					'sharing_group_id' => $result['Event']['sharing_group_id'],
					'post_count' => 0,
					'org_id' => $result['Event']['orgc_id']
			);
			$this->Thread->save($newThread);
			$thread = ($this->Thread->read());
		} else {
			if ($thread['Thread']['distribution'] != $result['Event']['distribution']) {
				$thread['Thread']['distribution'] = $result['Event']['distribution'];
				$this->Thread->save($thread);
			}
			if ($thread['Thread']['sharing_group_id'] != $result['Event']['sharing_group_id']) {
				$thread['Thread']['sharing_group_id'] = $result['Event']['sharing_group_id'];
				$this->Thread->save($thread);
			}
		}
		$this->loadModel('Post');
		$this->paginate['Post'] = array(
				'limit' => 5,
				'conditions' => array('Post.thread_id' => $thread['Thread']['id']),
				'contain' => array('User' => array('Organisation' => array('fields' => array('id', 'name')))),
		);
		$posts = $this->paginate('Post');
		if (!$this->_isSiteAdmin()) {
			foreach ($posts as &$post) {
				if ($post['User']['org_id'] != $this->Auth->user('org_id')) {
					$post['User']['email'] = 'User ' . $post['User']['id'] . ' (' . $post['User']['org_id'] . ')';
				}
			}
		}
		// Show the discussion
		$this->set('posts', $posts);
		$this->set('thread_id', $thread['Thread']['id']);
		$this->set('myuserid', $this->Auth->user('id'));
		$this->set('thread_title', $thread['Thread']['title']);
		$this->disableCache();
		$this->layout = 'ajax';
		$this->render('/Elements/eventdiscussion');
	}


	public function view($thread_id, $eventView = false) {
		$post_id = false;
		if (isset($this->passedArgs['post_id'])) $post_id = $this->passedArgs['post_id'];
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
									'Organisation' => array(
											'fields' => array('id', 'name')
									),
							),
					),
			);
			$posts = $this->paginate('Post');
			if (!$this->_isSiteAdmin()) {
				foreach ($posts as &$post) {
					if ($post['User']['org_id'] != $this->Auth->user('org_id')) {
						$post['User']['email'] = 'User ' . $post['User']['id'] . ' (' . $post['User']['org_id'] . ')';
					}
				}
			}
			$this->set('posts', $posts);
			$this->set('post_id', $post_id);
			$this->set('thread_id', $thread_id);
			$this->set('thread_title', $thread['Thread']['title']);
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
					'AND' => array(
							'Thread.distribution' => 0,
							'Thread.org_id' => $this->Auth->user('org_id'),
					),
					'AND' => array(
							'Thread.distribution' => 4,
							'Thread.sharing_group_id' => $sgids,
					),
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
			foreach ($threadsBeforeEmailRemoval as &$thread) {
				if (empty($thread['Post'][0]['User']['org_id'])) $thread['Post'][0]['User']['email'] = 'Deactivated user';
				else if ($thread['Post'][0]['User']['org_id'] != $this->Auth->user('org_id')) $thread['Post'][0]['User']['email'] = 'User ' . $thread['Post'][0]['User']['id'] . " (" . $thread['Post'][0]['User']['Organisation']['name'] . ")";
			}
		}
		$this->set('threads', $threadsBeforeEmailRemoval);
		$this->loadModel('Event');
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}
}
?>
