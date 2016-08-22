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
			'contain' => array('Tag', 'SharingGroup'),
			'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
			'order' => array(
					'Feed.default' => 'DESC',
					'Feed.id' => 'ASC'
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
		$this->loadModel('Event');
		$this->set('distributionLevels', $this->Event->distributionLevels);
	}

	public function view($feedId) {
		$feed = $this->Feed->find('first', array('conditions' => array('Feed.id' => $feedId)));
	}

	public function add() {
		if ($this->request->is('post')) {
			if (isset($this->request->data['Feed']['pull_rules'])) $this->request->data['Feed']['rules'] = $this->request->data['Feed']['pull_rules'];
			if ($this->request->data['Feed']['distribution'] != 4) $this->request->data['Feed']['sharing_group_id'] = 0;
			$this->request->data['Feed']['default'] = 0;
			$result = $this->Feed->save($this->request->data);
			if ($result) {
				$this->Session->setFlash('Feed added.');
				$this->redirect(array('controller' => 'feeds', 'action' => 'index'));
			}
			else $this->Session->setFlash('Feed could not be added.');
		} else {
			$this->loadModel('Event');
			$sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name',  1);
			$distributionLevels = $this->Event->distributionLevels;
			if (empty($sgs)) unset($distributionLevels[4]);
			$this->set('distributionLevels', $distributionLevels);
			$this->set('sharingGroups', $sgs);
			$tags = $this->Event->EventTag->Tag->find('list', array('fields' => array('Tag.name'), 'order' => array('lower(Tag.name) asc')));
			$tags[0] = 'None';
			$this->set('tags', $tags);
		}
	}

	public function edit($feedId) {
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		$this->Feed->read();
		if ($this->request->is('post') || $this->request->is('put')) {
			if (isset($this->request->data['Feed']['pull_rules'])) $this->request->data['Feed']['rules'] = $this->request->data['Feed']['pull_rules'];
			if ($this->request->data['Feed']['distribution'] != 4) $this->request->data['Feed']['sharing_group_id'] = 0;
			$this->request->data['Feed']['id'] = $feedId;
			$fields = array('id', 'name', 'provider', 'enabled', 'rules', 'url', 'distribution', 'sharing_group_id', 'tag_id');
			$feed = array();
			foreach ($fields as $field) $feed[$field] = $this->request->data['Feed'][$field];
			$result = $this->Feed->save($feed);
			if ($result) {
				$this->Session->setFlash('Feed updated.');
				$this->redirect(array('controller' => 'feeds', 'action' => 'index'));
			}
			else $this->Session->setFlash('Feed could not be updated.');
		} else {
			$this->request->data = $this->Feed->data;
			$this->request->data['Feed']['pull_rules'] = $this->request->data['Feed']['rules'];
			$this->loadModel('Event');
			$sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name',  1);
			$distributionLevels = $this->Event->distributionLevels;
			if (empty($sgs)) unset($distributionLevels[4]);
			$this->set('distributionLevels', $distributionLevels);
			$this->set('sharingGroups', $sgs);
			$tags = $this->Event->EventTag->Tag->find('list', array('fields' => array('Tag.name'), 'order' => array('lower(Tag.name) asc')));
			$tags[0] = 'None';
			$this->set('tags', $tags);
		}
	}

	public function delete($feedId) {
		if (!$this->request->is('post')) throw new MethodNotAllowedException('This action requires a post request.');
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		if ($this->Feed->delete($feedId)) $this->Session->setFlash('Feed deleted.');
		else $this->Session->setFlash('Feed could not be deleted.');
		$this->redirect(array('controller' => 'feeds', 'action' => 'index'));
	}

	public function fetchFromFeed($feedId) {
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		$this->Feed->read();
		if (!$this->Feed->data['Feed']['enabled']) {
			$this->Session->setFlash('Feed is currently not enabled. Make sure you enable it.');
			$this->redirect(array('action' => 'index'));
		}
		if (Configure::read('MISP.background_jobs')) {
			$this->loadModel('Job');
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'fetch_feed',
					'job_input' => 'Feed: ' . $feedId,
					'status' => 0,
					'retries' => 0,
					'org' => $this->Auth->user('Organisation')['name'],
					'message' => 'Starting fetch from Feed.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
			$process_id = CakeResque::enqueue(
					'default',
					'ServerShell',
					array('fetchFeed', $this->Auth->user('id'), $feedId, $jobId)
			);
			$this->Job->saveField('process_id', $process_id);
			$message = 'Pull queued for background execution.';
		} else {
			$result = $this->Feed->downloadFromFeedInitiator($feedId, $this->Auth->user());
			$message = 'Fetching the feed has successfuly completed.';
			if (isset($result['add'])) $message .= ' Downloaded ' . count($result['add']) . ' new event(s).';
			if (isset($result['edit'])) $message .= ' Updated ' . count($result['edit']) . ' event(s).';
		}
		$this->Session->setFlash($message);
		$this->redirect(array('action' => 'index'));
	}

	public function getEvent($feedId, $eventUuid, $all = false) {
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		$this->Feed->read();
		if (!$this->Feed->data['Feed']['enabled']) {
			$this->Session->setFlash('Feed is currently not enabled. Make sure you enable it.');
			$this->redirect(array('action' => 'previewIndex', $feedId));
		}
		$result = $this->Feed->downloadAndSaveEventFromFeed($this->Feed->data, $eventUuid, $this->Auth->user());
		if (isset($result['action'])) {
			if ($result['result']) {
				if ($result['action'] == 'add') $message = 'Event added.';
				else {
					if ($result['result'] === 'No change') $message = 'Event already up to date.';
					else $message = 'Event updated.';
				}
			} else {
				$message = 'Could not ' . $result['action'] . ' event.';
			}
		} else $message = 'Download failed.';
		$this->Session->setFlash($message);
		$this->redirect(array('action' => 'previewIndex', $feedId));
	}

	public function previewIndex($feedId) {
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		if (isset($this->passedArgs['pages'])) $currentPage = $this->passedArgs['pages'];
		else $currentPage = 1;
		$urlparams = '';
		$passedArgs = array();

		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		$this->Feed->read();
		$HttpSocket = $syncTool->setupHttpSocketFeed($this->Feed->data);
		$events = $this->Feed->getManifest($this->Feed->data, $HttpSocket);
		if (isset($events['code'])) throw new NotFoundException('Feed could not be fetched. The HTTP error code returned was: ' .$events['code']);
		$pageCount = count($events);
		App::uses('CustomPaginationTool', 'Tools');
		$customPagination = new CustomPaginationTool();
		$params = $customPagination->createPaginationRules($events, $this->passedArgs, $this->alias);
		$this->params->params['paging'] = array($this->modelClass => $params);
		if (is_array($events)) $customPagination->truncateByPagination($events, $params);
		else ($events = array());

		$this->set('events', $events);
		$this->loadModel('Event');
		$threat_levels = $this->Event->ThreatLevel->find('all');
		$this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		$this->set('distributionLevels', $this->Event->distributionLevels);
		$shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');
		$this->set('shortDist', $shortDist);
		$this->set('id', $feedId);
		$this->set('feed', $this->Feed->data);
		$this->set('urlparams', $urlparams);
		$this->set('passedArgs', json_encode($passedArgs));
		$this->set('passedArgsArray', $passedArgs);
	}


	public function previewEvent($feedId, $eventUuid, $all = false) {
		$this->Feed->id = $feedId;
		if (!$this->Feed->exists()) throw new NotFoundException('Invalid feed.');
		$this->Feed->read();
		$event = $this->Feed->downloadEventFromFeed($this->Feed->data, $eventUuid, $this->Auth->user());
		if (is_array($event)) {
			$this->loadModel('Event');
			$params = $this->Event->rearrangeEventForView($event, $this->passedArgs, $all);
			$this->params->params['paging'] = array('Feed' => $params);
			$this->set('event', $event);
			$this->set('feed', $this->Feed->data);
			$this->loadModel('Event');
			$dataForView = array(
					'Attribute' => array('attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels'),
					'Event' => array('eventDescriptions' => 'fieldDescriptions', 'analysisLevels' => 'analysisLevels')
			);
			foreach ($dataForView as $m => $variables) {
				if ($m === 'Event') $currentModel = $this->Event;
				else if ($m === 'Attribute') $currentModel = $this->Event->Attribute;
				foreach ($variables as $alias => $variable) {
					$this->set($alias, $currentModel->{$variable});
				}
			}
			$threat_levels = $this->Event->ThreatLevel->find('all');
			$this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
		} else {
			if ($event === 'blocked') throw new MethodNotAllowedException('This event is blocked by the Feed filters.');
			else throw new NotFoundException('Could not download the selected Event');
		}
	}

	public function enable($id) {
		$result = $this->__toggleEnable($id, true);
		$this->set('name', $result['message']);
		$this->set('message', $result['message']);
		$this->set('url', $this->here);
		if ($result) {
			$this->set('_serialize', array('name', 'message', 'url'));
		} else {
			$this->set('errors', $result);
			$this->set('_serialize', array('name', 'message', 'url', 'errors'));
		}
	}

	public function disable($id) {
		$result = $this->__toggleEnable($id, false);
		$this->set('name', $result['message']);
		$this->set('message', $result['message']);
		$this->set('url', $this->here);
		if ($result['result']) {
			$this->set('_serialize', array('name', 'message', 'url'));
		} else {
			$this->set('errors', $result);
			$this->set('_serialize', array('name', 'message', 'url', 'errors'));
		}
	}

	private function __toggleEnable($id, $enable = true) {
		if (!is_numeric($id)) throw new MethodNotAllowedException('Invalid Feed.');
		$this->Feed->id = $id;
		if (!$this->Feed->exists()) throw new MethodNotAllowedException('Invalid Feed.');
		$feed = $this->Feed->find('first', array(
				'conditions' => array('Feed.id' => $id),
				'recursive' => -1
		));
		$feed['Feed']['enabled'] = $enable;
		$result = array('result' => $this->Feed->save($feed));
		$fail = false;
		if (!$result['result']) {
			$fail = true;
			$result['result'] = $this->Feed->validationErrors;
		}
		$action = $enable ? 'enable' : 'disable';
		$result['message'] = $fail ? 'Could not ' . $action . ' feed.' : 'Feed ' . $action . 'd.';
		return $result;
	}
}
