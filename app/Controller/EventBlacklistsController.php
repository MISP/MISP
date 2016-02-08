<?php
App::uses('AppController', 'Controller');

class EventBlacklistsController extends AppController {
	public $components = array('Session', 'RequestHandler');

	public function beforeFilter() {
		parent::beforeFilter();
		if(!$this->_isSiteAdmin()) $this->redirect('/');
		if (!Configure::read('MISP.enableEventBlacklisting')) {
			$this->Session->setFlash(__('Event Blacklisting is not currently enabled on this instance.'));
			$this->redirect('/');
		}
	}

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
			'order' => array(
					'EventBlacklist.created' => 'DESC'
			),
	);

	public function index() {
		if ($this->response->type() === 'application/json' || $this->response->type() == 'application/xml' || $this->_isRest()) {
			$blackList = $this->paginate();
			$eventBlacklist= array();
			foreach ($blackList as $item) {
				$eventBlacklist[] = $item['EventBlacklist'];
			}
			$this->set('EventBlacklist', $eventBlacklist);
			$this->set('_serialize', 'EventBlacklist');
		} else {
			$this->set('response', $this->paginate());
		}
	}

	public function add() {
		if ($this->request->is('post')) {
			if ($this->_isRest()) {
				if ($this->response->type() === 'application/json') {
					$isJson = true;
					$data = $this->request->input('json_decode', true);
				} else  {
					$data = $this->request->data;
				}
				if (isset($data['request'])) $data = $data['request'];
			} else {
				$data = $this->request->data;
			}
			if (is_array($data['EventBlacklist']['uuids'])) $uuids = $data['EventBlacklist']['uuids'];
			else $uuids = explode(PHP_EOL, $data['EventBlacklist']['uuids']);
			$successes = array();
			$fails = array();
			foreach ($uuids as $uuid) {
				$uuid = trim($uuid);
				if (strlen($uuid) == 36) {
					$this->EventBlacklist->create();
					if ($this->EventBlacklist->save(
							array(
								'event_uuid' => $uuid, 
								'comment' => !empty($data['EventBlacklist']['comment']) ? $data['EventBlacklist']['comment'] : '', 
								'event_info' => !empty($data['EventBlacklist']['info']) ? $data['EventBlacklist']['info'] : '',
								'event_orgc' => !empty($data['EventBlacklist']['orgc']) ? $data['EventBlacklist']['orgc'] : '',
							)
						)
					) {
						$successes[] = $uuid;
					} else {
						$fails[] = $uuid;
					}
				} else {
					$fails[] = $uuid;
				}
			}
			$message = 'Done. Added ' . count($successes) . ' new entries to the blacklist. ' . count($fails) . ' entries could not be saved.';
			if ($this->_isRest()) {
				$this->set('result', array('successes' => $successes, 'fails' => $fails));
				$this->set('message', $message);
				$this->set('_serialize', array('message', 'result'));
			} else {
				$this->Session->setFlash(__($message));
				$this->redirect(array('action' => 'index'));
			}
		}
	}
	
	public function edit($id) {
		if (strlen($id) == 36) {
			$eb = $this->EventBlacklist->find('first', array('conditions' => array('uuid' => $id)));
		} else {
			$eb = $this->EventBlacklist->find('first', array('conditions' => array('id' => $id)));
		}
		if (empty($eb)) throw new NotFoundException('Blacklist item not found.');
		$this->set('eb', $eb);
		if ($this->request->is('post')) {
			if ($this->_isRest()) {
				if ($this->response->type() === 'application/json') {
					$isJson = true;
					$data = $this->request->input('json_decode', true);
				} else  {
					$data = $this->request->data;
				}
				if (isset($data['request'])) $data = $data['request'];
			} else {
				$data = $this->request->data;
			}
			$fields = array('comment', 'event_info', 'event_orgc');
			foreach ($fields as $f) {
				if (isset($data['EventBlacklist'][$f])) $eb['EventBlacklist'][$f] = $data['EventBlacklist'][$f];
			}
			if ($this->EventBlacklist->save($eb)) {
				if ($this->_isRest()) {
					$this->set('message', array('Blacklist item added.'));
					$this->set('_serialize', array('message'));
				} else {
					$this->Session->setFlash(__('Blacklist item added.'));
					$this->redirect(array('action' => 'index'));
				}
			} else {
				if ($this->_isRest()) {
					throw new MethodNotAllowedException('Could not save the blacklist item.');
				} else {
					$this->Session->setFlash('Could not save the blacklist item');
					$this->redirect(array('action' => 'index'));
				}
			}
		}
	}

	public function delete($id) {
		if (strlen($id) == 36) {
			$eb = $this->EventBlacklist->find('first', array(
				'fields' => array('id'),
				'conditions' => array('event_uuid' => $id),
			));
			$id = $eb['EventBlacklist']['id'];
		}
		if (!$this->request->is('post') && !$this->_isRest()) {
			throw new MethodNotAllowedException();
		}
		
		$this->EventBlacklist->id = $id;
		if (!$this->EventBlacklist->exists()) {
			throw new NotFoundException(__('Invalid blacklist entry'));
		}

		if ($this->EventBlacklist->delete()) {
			$this->Session->setFlash(__('Blacklist entry removed'));
		} else {
			$this->Session->setFlash(__('Could not remove the blacklist entry'));
		}
		$this->redirect(array('action' => 'index'));
	}
	
	
}
