<?php

App::uses('AppController', 'Controller');

/**
 * Posts Controller
 *
 */
class PostsController extends AppController {

	public $components = array(
		'Security',
		'Session',
		'RequestHandler'
	);

	public $helpers = array('Js' => array('Jquery'));
	
	public $paginate = array(
			'limit' => 60,
	);

	public function beforeFilter() {
		parent::beforeFilter();
	}
	
	// Find the thread_id and post_id in advance. If a user clicks post comment on the event view, send the event's related thread's ID 
	// Usage:
	// /posts/add : Creates new thread with the added post as the first post. Title set by user
	// /posts/add/event/id : Checks if the event already has a thread, if no it creates one. The post is added to the event's thread
	// /posts/add/thread/id : Adds a post to the thread specified
	// /posts/add/post/id : Adds a post as a reply to another post. The system finds the appropriate thread, adds the post to the thread and links to the post that is being replied to. 
	public function add($target_type = null, $target_id = null, $quick = false) {
		$this->loadModel('Thread');
		$this->Thread->recursive = -1;
		$distribution = 1;
		$event_id = 0;
		$post_id = 0;
		// we have a target type and a target id. The target id defines what type of object we want to attach this event to (is it a reply to another post, 
		// did someone add a post to a thread, does a thread for the event exist already, etc. 
		switch ($target_type) {
			case 'event' :
				$this->loadModel('Event');
				$this->Event->recursive = -1;
				$this->Event->read(null, $target_id);
				$eventDiscussionTitle = 'Discussion about Event #' . $this->Event->data['Event']['id'] . ' (' . $this->Event->data['Event']['info'] . ')';
				if (!$this->Event->exists()) {
					throw new NotFoundException(__('Invalid event'));
				}
				if (!$this->_isSiteAdmin()) {
					if ($this->Event->data['Event']['distribution'] == 0 && $this->Event->data['Event']['org'] != $this->Auth->user('org')) {
						throw new MethodNotAllowedException('You don\'t have permission to do that.');
					}
				}
				$thread = $this->Thread->find('first', array('conditions' => array('event_id' => $target_id)));
				$title = $eventDiscussionTitle;
				if (isset($thread['Thread']['id'])) {
					$target_thread_id = $thread['Thread']['id'];
				} else {
					$target_thread_id = null;
				}
				$distribution = $this->Event->data['Event']['distribution'];
				$org = $this->Event->data['Event']['org'];
			break;
			case 'thread' :
				$target_thread_id = $target_id;
				if ($target_id != null) {
					$thread = $this->Thread->read(null, $target_thread_id);
					if ($thread == null) {
						throw new NotFoundException(__('Invalid thread'));
					}
					if (!$this->_isSiteAdmin()) {
						if ($thread['Thread']['distribution'] == 0 && $this->Auth->user('org') != $thread['Thread']['org']) {
							throw new MethodNotAllowedException('You don\'t have permission to do that.');
						}
					}
					$title = $this->Thread->data['Thread']['title'];
				}
			break;
			case 'post' :
				$this->Post->read(null, $target_id);
				$target_thread_id = $this->Post->data['Post']['thread_id'];
				$thread = $this->Thread->read(null, $target_thread_id);
				if (!$this->_isSiteAdmin()) {
					if ($thread['Thread']['distribution'] == 0 && $this->Auth->user('org') != $thread['Thread']['org']) {
						throw new MethodNotAllowedException('You don\'t have permission to do that.');
					}
				}
				$title = $this->Thread->data['Thread']['title'];
				$previousPost = $this->_grabPreviousPost($target_id);
				$distribution = $previousPost['Thread']['distribution'];
				$event_id = $previousPost['Thread']['event_id'];
				$post_id = $target_id;
				$target_thread_id = $previousPost['Thread']['id'];
			break;
			default:
				$target_thread_id = null;
			break;
		}

		if ($this->request->is('post')) {
			// Set the default values that we'll alter before actually saving data. These are the default values unless specifically modified.
			// By default, all discussions will be visibile to everyone on the platform
			$org = $this->Auth->user('org');
			// Set the title if it is setable in the add view.
			if (empty($thread_id) && empty($target_type)) {
				$title = $this->request->data['Post']['title'];
			}
			
			if ($target_thread_id == null) {
				// We have a post that was posted in a new thread. This could also mean that someone created the first post related to an event!
				$this->Thread->create();
				// Take the title from above and the id of the event as event_id if we are adding a post to an event. 
				if ($target_type === 'event') {
					$title = $eventDiscussionTitle;
					$event_id = $this->Event->data['Event']['id'];
				}
				$newThread = array(
						'date_created' => date('Y/m/d H:i:s'),
						'date_modified' => date('Y/m/d H:i:s'),
						'user_id' => $this->Auth->user('id'),
						'event_id' => $event_id,
						'title' => $title,
						'distribution' => $distribution,
						'post_count' => 1,
						'org' => $org
				);
				$this->Thread->save($newThread);
				$target_thread_id = $this->Thread->getId();
			} else {
				// In this case, we have a post that was posted in an already existing thread. Update the thread!
				$this->Thread->read(null, $target_thread_id);
				$this->Thread->data['Thread']['date_modified'] = date('Y/m/d H:i:s');
				$this->Thread->save();
			}
			
			// Time to create our post! 
			$this->Post->create();
			$newPost = array(
					'date_created' => date('Y/m/d H:i:s'),
					'date_modified' => date('Y/m/d H:i:s'),
					'user_id' => $this->Auth->user('id'),
					'contents' => $this->request->data['Post']['message'],
					'post_id' => $post_id,
					'thread_id' => $target_thread_id, 
			);
			if ($this->Post->save($newPost)) {
				$this->Thread->recursive = 0;
				$this->Thread->contain('Post');
				$this->Thread->read(null, $target_thread_id);
				$this->Thread->updateAfterPostChange(true);
				$this->Session->setFlash(__('Post added'));
				$this->redirect(array('action' => 'view', $this->Post->getId()));
			} else {
				$this->Session->setFlash('The post could not be added.');
			}
		}
		if ($target_type === 'post') {
			$this->set('previous', $previousPost['Post']['contents']);
		}
		$this->set('thread_id', $target_thread_id);
		$this->set('target_type', $target_type);
		$this->set('target_id', $target_id);
		if (isset($title)) {
			$this->set('title', $title);
		}
	}
	
	public function edit($post_id) {
		$this->Post->id = $post_id;
		if (!$this->Post->exists()) {
			throw new NotFoundException(__('Invalid post'));
		}
		$this->Post->recursive = 1; 
		$this->Post->read(null, $post_id);
		if (!$this->_isSiteAdmin() && $this->Auth->user('id') != $this->Post->data['Post']['user_id']) {
			throw new MethodNotAllowedException('This is not your event.');
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			$this->request->data['Post']['date_modified'] = date('Y/m/d H:i:s');
			$fieldList = array('date_modified', 'contents');
			if ($this->Post->save($this->request->data, true, $fieldList)) {
				$this->Session->setFlash('Post edited');
				$this->loadModel('Thread');
				$this->Thread->recursive = 0;
				$this->Thread->contain('Post');
				$this->Thread->read(null, $this->Post->data['Post']['thread_id']);
				$this->Thread->updateAfterPostChange();
				$this->redirect(array('action' => 'view', $post_id));
			} else {
				$this->Session->setFlash('The Post could not be edited. Please, try again.');
			}
		}
		$this->set('title', $this->Post->data['Thread']['title']);
		$this->set('contents', $this->Post->data['Post']['contents']);
		$this->set('id', $post_id);
		$this->set('thread_id', $this->Post->data['Post']['thread_id']);
	}
	
	public function quick_add() {
		if($this->RequestHandler->isAjax()) {
			$this->layout = 'ajax'; //THIS LINE NEWLY ADDED
			if(!empty($this->data)) {
				if($this->Message->save($this->data)) {
					$this->Session->setFlash('Your Message has been posted');
				}
			}
		}
	}
	
	
	public function quick_edit() {
		throw new Exception();
		if($this->RequestHandler->isAjax()) {
			$this->layout = 'ajax'; //THIS LINE NEWLY ADDED
			if(!empty($this->data)) {
				if($this->Message->save($this->data)) {
					$this->Session->setFlash('Your Message has been posted');
				}
			}
		}
	}
	
	public function delete($post_id) {
			if (!$this->request->is('post')) {
				throw new MethodNotAllowedException();
			}
			$this->Post->id = $post_id;
			if (!$this->Post->exists()) {
				throw new NotFoundException(__('Invalid post'));
			}
			$this->Post->read();
			$temp = $this->Post->data;
			if ($this->Auth->user('id') != $this->Post->data['Post']['user_id'] && !$this->_isSiteAdmin()) {
				throw new MethodNotAllowedException('This post doesn\'t belong to you, so you cannot delete it.');
			}
			if ($this->Post->delete()) {
				$this->loadModel('Thread');
				$this->Thread->recursive = 0;
				$this->Thread->contain('Post');
				$this->Thread->read(null, $this->Post->data['Thread']['id']);
				$thread = $this->Thread->data['Thread']['id'];
				if (!$this->Thread->updateAfterPostChange()) {
					$this->Session->setFlash('Post and thread deleted');
					$this->redirect(array('controller' => 'threads', 'action' => 'index'));
				} else {
					$this->Session->setFlash('Post deleted');
				}
			}
			$this->redirect(array('controller' => 'threads', 'action' => 'view', $thread));

	}

	
	// Views the proper context for the post
	public function view($post_id) {
		$this->Post->id = $post_id;
		if (!$this->Post->exists()) {
			throw new NotFoundException(__('Invalid post'));
		}
		$this->Post->read();
		// We don't know what the context was, so let's try to guess what the user wants to see!
		// If the post belongs to an event's discussion thread, redirect the user to the event's view
		if ($this->Post->data['Thread']['event_id'] != 0) {
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->Post->data['Thread']['event_id']));
		} else {
		//Otherwise send the user to the thread's index.
			$this->redirect(array('controller' => 'threads',  'action' => 'view', $this->Post->data['Thread']['id']));
		}
	}
	
	private function _grabPreviousPost($post_id) {
		$this->Post->id = $post_id;
		$this->Post->read();
		return $this->Post->data;
	}
	
}
?>
		