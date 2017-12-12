<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

class ServersController extends AppController {

	public $components = array('Security' ,'RequestHandler');	// XXX ACL component

	public $paginate = array(
			'limit' => 60,
			'recursive' => -1,
			'contain' => array(
					'User' => array(
							'fields' => array('User.id', 'User.org_id', 'User.email'),
					),
					'Organisation' => array(
							'fields' => array('Organisation.name', 'Organisation.id'),
					),
					'RemoteOrg' => array(
							'fields' => array('RemoteOrg.name', 'RemoteOrg.id'),
					),
			),
			'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
			'order' => array(
					'Server.url' => 'ASC'
			),
	);

	public $uses = array('Server', 'Event');

	public function beforeFilter() {
		parent::beforeFilter();

		// permit reuse of CSRF tokens on some pages.
		switch ($this->request->params['action']) {
			case 'push':
			case 'pull':
			case 'getVersion':
			case 'testConnection':
				$this->Security->csrfUseOnce = false;
		}
	}

	public function index() {
		if (!$this->_isSiteAdmin()) {
			if (!$this->userRole['perm_sync'] && !$this->userRole['perm_admin']) $this->redirect(array('controller' => 'events', 'action' => 'index'));
			$this->paginate['conditions'] = array('Server.org_id LIKE' => $this->Auth->user('org_id'));
		}
		$this->set('servers', $this->paginate());
		$collection = array();
		$collection['orgs'] = $this->Server->Organisation->find('list', array(
				'fields' => array('id', 'name'),
		));
		$this->loadModel('Tag');
		$collection['tags'] = $this->Tag->find('list', array(
				'fields' => array('id', 'name'),
		));
		$this->set('collection', $collection);

	}

	public function previewIndex($id) {
		$urlparams = '';
		$passedArgs = array();
		if (!$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException('You are not authorised to do that.');
		}
		$server = $this->Server->find('first', array('conditions' => array('Server.id' => $id), 'recursive' => -1, 'fields' => array('Server.id', 'Server.url', 'Server.name')));
		if (empty($server)) throw new NotFoundException('Invalid server ID.');
		$validFilters = $this->Server->validEventIndexFilters;
		foreach ($validFilters as $k => $filter) {
			if (isset($this->passedArgs[$filter])) {
				$passedArgs[$filter] = $this->passedArgs[$filter];
				if ($k != 0) $urlparams .= '/';
				$urlparams .= $filter . ':' . $this->passedArgs[$filter];
			}
		}
		$combinedArgs = array_merge($this->passedArgs, $passedArgs);
		if (!isset($combinedArgs['sort'])) {
			$combinedArgs['sort'] = 'timestamp';
			$combinedArgs['direction'] = 'desc';
		}
		$events = $this->Server->previewIndex($id, $this->Auth->user(), $combinedArgs);
		$this->loadModel('Event');
		$threat_levels = $this->Event->ThreatLevel->find('all');
		$this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
		App::uses('CustomPaginationTool', 'Tools');
		$customPagination = new CustomPaginationTool();
		$params = $customPagination->createPaginationRules($events, $this->passedArgs, $this->alias);
		$this->params->params['paging'] = array($this->modelClass => $params);
		if (is_array($events)) $customPagination->truncateByPagination($events, $params);
		else ($events = array());
		$this->set('events', $events);
		$this->set('eventDescriptions', $this->Event->fieldDescriptions);
		$this->set('analysisLevels', $this->Event->analysisLevels);
		$this->set('distributionLevels', $this->Event->distributionLevels);

		$shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');
		$this->set('shortDist', $shortDist);
		$this->set('ajax', $this->request->is('ajax'));
		$this->set('id', $id);
		$this->set('urlparams', $urlparams);
		$this->set('passedArgs', json_encode($passedArgs));
		$this->set('passedArgsArray', $passedArgs);
		$this->set('server', $server);
	}

	public function previewEvent($serverId, $eventId, $all = false) {
		if (!$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException('You are not authorised to do that.');
		}
		$server = $this->Server->find('first', array('conditions' => array('Server.id' => $serverId), 'recursive' => -1, 'fields' => array('Server.id', 'Server.url', 'Server.name')));
		if (empty($server)) throw new NotFoundException('Invalid server ID.');
		$event = $this->Server->previewEvent($serverId, $eventId);
		// work on this in the future to improve the feedback
		// 2 = wrong error code
		if (is_numeric($event))throw new NotFoundException('Invalid event.');
		$this->loadModel('Event');
		$params = $this->Event->rearrangeEventForView($event, $this->passedArgs, $all);
		$this->params->params['paging'] = array('Server' => $params);
		$this->set('event', $event);
		$this->set('server', $server);
		$this->loadModel('Event');
		$dataForView = array(
				'Attribute' => array('attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels'),
				'Event' => array('eventDescriptions' => 'fieldDescriptions', 'analysisLevels' => 'analysisLevels'),
				'Object' => array()
		);
		foreach ($dataForView as $m => $variables) {
			if ($m === 'Event') $currentModel = $this->Event;
			else if ($m === 'Attribute') $currentModel = $this->Event->Attribute;
			else if ($m === 'Object') $currentModel = $this->Event->Object;
			foreach ($variables as $alias => $variable) {
				$this->set($alias, $currentModel->{$variable});
			}
		}
		$threat_levels = $this->Event->ThreatLevel->find('all');
		$this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
	}

	public function filterEventIndex($id) {
		if (!$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException('You are not authorised to do that.');
		}
		$validFilters = $this->Server->validEventIndexFilters;
		$validatedFilterString = '';
		foreach ($this->passedArgs as $k => $v) {
			if (in_array('' . $k, $validFilters)) {
				if ($validatedFilterString != '') $validatedFilterString .= '/';
				$validatedFilterString .= $k . ':' . $v;
			}
		}
		$this->set('id', $id);
		$this->set('validFilters', $validFilters);
		$this->set('filter', $validatedFilterString);
	}

	public function add() {
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if ($this->request->is('post')) {
			if($this->_isRest()) {
				if (!isset($this->request->data['Server'])) {
					$this->request->data = array('Server' => $this->request->data);
				}
			}
			$json = json_decode($this->request->data['Server']['json'], true);

			$fail = false;
			if (empty(Configure::read('MISP.host_org_id'))) $this->request->data['Server']['internal'] = 0;
			// test the filter fields
			if (!empty($this->request->data['Server']['pull_rules']) && !$this->Server->isJson($this->request->data['Server']['pull_rules'])) {
				$fail = true;
				$error_msg = __('The pull filter rules must be in valid JSON format.');
				if($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'add', false, array('pull_rules' => $error_msg), $this->response->type());
				} else {
					$this->Session->setFlash($error_msg);
				}
			}

			if (!$fail && !empty($this->request->data['Server']['push_rules']) && !$this->Server->isJson($this->request->data['Server']['push_rules'])) {
				$fail = true;
				$error_msg = __('The push filter rules must be in valid JSON format.');
				if($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'add', false, array('push_rules' => $error_msg), $this->response->type());
				} else {
					$this->Session->setFlash($error_msg);
				}
			}

			if (!$fail) {
				// force check userid and orgname to be from yourself
				$this->request->data['Server']['org_id'] = $this->Auth->user('org_id');
				if ($this->request->data['Server']['organisation_type'] < 2) $this->request->data['Server']['remote_org_id'] = $json['id'];
				else {
					$existingOrgs = $this->Server->Organisation->find('first', array(
							'conditions' => array('uuid' => $json['uuid']),
							'recursive' => -1,
							'fields' => array('id', 'uuid')
					));
					if (!empty($existingOrgs)) {
						$fail = true;
						if($this->_isRest()) {
							return $this->RestResponse->saveFailResponse('Servers', 'add', false, array('Organisation' => 'Remote Organisation\'s uuid already used'), $this->response->type());
						} else {
							$this->Session->setFlash(__('That organisation could not be created as the uuid is in use already.'));
						}
					}

					if (!$fail) {
						$this->Server->Organisation->create();
						$orgSave = $this->Server->Organisation->save(array(
								'name' => $json['name'],
								'uuid' => $json['uuid'],
								'local' => 0,
								'created_by' => $this->Auth->user('id')
						));

						if (!$orgSave) {
							if($this->_isRest()) {
								return $this->RestResponse->saveFailResponse('Servers', 'add', false, $this->Server->Organisation->validationError, $this->response->type());
							} else {
								$this->Session->setFlash(__('Couldn\'t save the new organisation, are you sure that the uuid is in the correct format?.'));
							}
							$fail = true;
							$this->request->data['Server']['external_name'] = $json['name'];
							$this->request->data['Server']['external_uuid'] = $json['uuid'];
						} else {
							$this->request->data['Server']['remote_org_id'] = $this->Server->Organisation->id;
						}
					}
				}
				if (Configure::read('MISP.host_org_id') == 0 || $this->request->data['Server']['remote_org_id'] != Configure::read('MISP.host_org_id')) {
					$this->request->data['Server']['internal'] = 0;
				}
				if (!$fail) {
					$this->request->data['Server']['org_id'] = $this->Auth->user('org_id');
					if ($this->Server->save($this->request->data)) {
						if (isset($this->request->data['Server']['submitted_cert']) && $this->request->data['Server']['submitted_cert']['size'] != 0) {
							$this->__saveCert($this->request->data, $this->Server->id, false);
						}
						if (isset($this->request->data['Server']['submitted_client_cert']) && $this->request->data['Server']['submitted_client_cert']['size'] != 0) {
							$this->__saveCert($this->request->data, $this->Server->id, true);
						}
						if($this->_isRest()) {
							$server = $this->Server->find('first', array(
									'conditions' => array('Server.id' => $this->Server->id),
									'recursive' => -1
							));
							return $this->RestResponse->viewData($server, $this->response->type());
						} else {
							$this->Session->setFlash(__('The server has been saved'));
							$this->redirect(array('action' => 'index'));
						}
					} else {
						if($this->_isRest()) {
							return $this->RestResponse->saveFailResponse('Servers', 'add', false, $this->Server->validationError, $this->response->type());
						} else {
							$this->Session->setFlash(__('The server could not be saved. Please, try again.'));
						}
					}
				}
			}
		}
		if($this->_isRest()) {
			return $this->RestResponse->describe('Servers', 'add', false, $this->response->type());
		} else {
			$organisationOptions = array(0 => 'Local organisation', 1 => 'External organisation', 2 => 'New external organisation');
			$temp = $this->Server->Organisation->find('all', array(
					'conditions' => array('local' => true),
					'fields' => array('id', 'name'),
					'order' => array('lower(Organisation.name) ASC')
			));
			$localOrganisations = array();
			$allOrgs = array();
			foreach ($temp as $o) {
				$localOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
				$allOrgs[] = array('id' => $o['Organisation']['id'], 'name' => $o['Organisation']['name']);
			}
			$temp = $this->Server->Organisation->find('all', array(
					'conditions' => array('local' => false),
					'fields' => array('id', 'name'),
					'order' => array('lower(Organisation.name) ASC')
			));
			$externalOrganisations = array();
			foreach ($temp as $o) {
				$externalOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
				$allOrgs[] = array('id' => $o['Organisation']['id'], 'name' => $o['Organisation']['name']);
			}
			$this->set('host_org_id', Configure::read('MISP.host_org_id'));
			$this->set('organisationOptions', $organisationOptions);
			$this->set('localOrganisations', $localOrganisations);
			$this->set('externalOrganisations', $externalOrganisations);
			$this->set('allOrganisations', $allOrgs);

			// list all tags for the rule picker
			$this->loadModel('Tag');
			$temp = $this->Tag->find('all', array('recursive' => -1));
			$allTags = array();
			foreach ($temp as $t) $allTags[] = array('id' => $t['Tag']['id'], 'name' => $t['Tag']['name']);
			$this->set('allTags', $allTags);
			$this->set('host_org_id', Configure::read('MISP.host_org_id'));
		}
	}

	public function edit($id = null) {
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		$s = $this->Server->read(null, $id);
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if ($this->request->is('post') || $this->request->is('put')) {
			if (empty(Configure::read('MISP.host_org_id'))) $this->request->data['Server']['internal'] = 0;
			if($this->_isRest()) {
				if (!isset($this->request->data['Server'])) {
					$this->request->data = array('Server' => $this->request->data);
				}
			}
			if(isset($this->request->data['Server']['json'])) {
				$json = json_decode($this->request->data['Server']['json'], true);
			} else {
				$json = NULL;
			}
			$fail = false;

			// test the filter fields
			if (!empty($this->request->data['Server']['pull_rules']) && !$this->Server->isJson($this->request->data['Server']['pull_rules'])) {
				$fail = true;
				$error_msg = __('The pull filter rules must be in valid JSON format.');
				if($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'edit', false, array('pull_rules' => $error_msg), $this->response->type());
				} else {
					$this->Session->setFlash($error_msg);
				}
			}

			if (!$fail && !empty($this->request->data['Server']['push_rules']) && !$this->Server->isJson($this->request->data['Server']['push_rules'])) {
				$fail = true;
				$error_msg = __('The push filter rules must be in valid JSON format.');
				if($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'edit', false, array('push_rules' => $error_msg), $this->response->type());
				} else {
					$this->Session->setFlash($error_msg);
				}
			}
			if (!$fail) {
				// say what fields are to be updated
				$fieldList = array('id', 'url', 'push', 'pull', 'unpublish_event', 'publish_without_email', 'remote_org_id', 'name' ,'self_signed', 'cert_file', 'client_cert_file', 'push_rules', 'pull_rules', 'internal');
				$this->request->data['Server']['id'] = $id;
				if (isset($this->request->data['Server']['authkey']) && "" != $this->request->data['Server']['authkey']) $fieldList[] = 'authkey';
				if(isset($this->request->data['Server']['organisation_type']) && isset($json)) {
					// adds 'remote_org_id' in the fields to update
					$fieldList[] = 'remote_org_id';
					if ($this->request->data['Server']['organisation_type'] < 2) $this->request->data['Server']['remote_org_id'] = $json['id'];
					else {
						$existingOrgs = $this->Server->Organisation->find('first', array(
								'conditions' => array('uuid' => $json['uuid']),
								'recursive' => -1,
								'fields' => array('id', 'uuid')
						));
						if (!empty($existingOrgs)) {
							$fail = true;
							if($this->_isRest()) {
								return $this->RestResponse->saveFailResponse('Servers', 'edit', false, array('Organisation' => 'Remote Organisation\'s uuid already used'), $this->response->type());
							} else {
								$this->Session->setFlash(__('That organisation could not be created as the uuid is in use already.'));
							}
						}

						if (!$fail) {
							$this->Server->Organisation->create();
							$orgSave = $this->Server->Organisation->save(array(
									'name' => $json['name'],
									'uuid' => $json['uuid'],
									'local' => 0,
									'created_by' => $this->Auth->user('id')
							));

							if (!$orgSave) {
								if($this->_isRest()) {
									return $this->RestResponse->saveFailResponse('Servers', 'edit', false, $this->Server->Organisation->validationError, $this->response->type());
								} else {
									$this->Session->setFlash(__('Couldn\'t save the new organisation, are you sure that the uuid is in the correct format?.'));
								}
								$fail = true;
								$this->request->data['Server']['external_name'] = $json['name'];
								$this->request->data['Server']['external_uuid'] = $json['uuid'];
							} else {
								$this->request->data['Server']['remote_org_id'] = $this->Server->Organisation->id;
							}
						}
					}
					if (empty(Configure::read('MISP.host_org_id')) || $this->request->data['Server']['remote_org_id'] != Configure::read('MISP.host_org_id')) {
						$this->request->data['Server']['internal'] = 0;
					}
				}
			}
			if (!$fail) {
				// Save the data
				if ($this->Server->save($this->request->data, true, $fieldList)) {
					if (isset($this->request->data['Server']['submitted_cert']) && $this->request->data['Server']['submitted_cert']['size'] != 0 && (!isset($this->request->data['Server']['delete_cert']) || !$this->request->data['Server']['delete_cert'])) {
						$this->__saveCert($this->request->data, $this->Server->id, false);
					} else {
						if (isset($this->request->data['Server']['delete_cert']) && $this->request->data['Server']['delete_cert']) $this->__saveCert($this->request->data, $this->Server->id, false, true);
					}
					if (isset($this->request->data['Server']['submitted_client_cert']) && $this->request->data['Server']['submitted_client_cert']['size'] != 0 && (!isset($this->request->data['Server']['delete_client_cert']) || !$this->request->data['Server']['delete_client_cert'])) {
						$this->__saveCert($this->request->data, $this->Server->id, true);
					} else {
						if (isset($this->request->data['Server']['delete_client_cert']) && $this->request->data['Server']['delete_client_cert']) $this->__saveCert($this->request->data, $this->Server->id, true, true);
					}
					if($this->_isRest()) {
						$server = $this->Server->find('first', array(
								'conditions' => array('Server.id' => $this->Server->id),
								'recursive' => -1
						));
						return $this->RestResponse->viewData($server, $this->response->type());
					} else {
						$this->Session->setFlash(__('The server has been saved'));
						$this->redirect(array('action' => 'index'));
					}
				} else {
					if($this->_isRest()) {
						return $this->RestResponse->saveFailResponse('Servers', 'edit', false, $this->Server->validationError, $this->response->type());
					} else {
						$this->Session->setFlash(__('The server could not be saved. Please, try again.'));
					}
				}
			}
		} else {
			$this->Server->read(null, $id);
			$this->Server->set('authkey', '');
			$this->request->data = $this->Server->data;
		}
		if($this->_isRest()) {
			return $this->RestResponse->describe('Servers', 'edit', false, $this->response->type());
		} else {
			$organisationOptions = array(0 => 'Local organisation', 1 => 'External organisation', 2 => 'New external organisation');
			$temp = $this->Server->Organisation->find('all', array(
					'conditions' => array('local' => true),
					'fields' => array('id', 'name'),
					'order' => array('lower(Organisation.name) ASC')
			));
			$localOrganisations = array();
			$allOrgs = array();
			foreach ($temp as $o) {
				$localOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
				$allOrgs[] = array('id' => $o['Organisation']['id'], 'name' => $o['Organisation']['name']);
			}
			$temp = $this->Server->Organisation->find('all', array(
					'conditions' => array('local' => false),
					'fields' => array('id', 'name'),
					'order' => array('lower(Organisation.name) ASC')
			));
			$externalOrganisations = array();
			foreach ($temp as $o) {
				$externalOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
				$allOrgs[] = array('id' => $o['Organisation']['id'], 'name' => $o['Organisation']['name']);
			}

			$oldRemoteSetting = 0;
			if (!$this->Server->data['RemoteOrg']['local']) $oldRemoteSetting = 1;
			$this->set('host_org_id', Configure::read('MISP.host_org_id'));
			$this->set('oldRemoteSetting', $oldRemoteSetting);
			$this->set('oldRemoteOrg', $this->Server->data['RemoteOrg']['id']);

			$this->set('organisationOptions', $organisationOptions);
			$this->set('localOrganisations', $localOrganisations);
			$this->set('externalOrganisations', $externalOrganisations);
			$this->set('allOrganisations', $allOrgs);

			// list all tags for the rule picker
			$this->loadModel('Tag');
			$temp = $this->Tag->find('all', array('recursive' => -1));
			$allTags = array();
			foreach ($temp as $t) $allTags[] = array('id' => $t['Tag']['id'], 'name' => $t['Tag']['name']);
			$this->set('allTags', $allTags);
			$this->set('server', $s);
			$this->set('host_org_id', Configure::read('MISP.host_org_id'));
		}
	}

	public function delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		$s = $this->Server->read(null, $id);
		if (!$this->_isSiteAdmin()) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if ($this->Server->delete()) {
			$this->Session->setFlash(__('Server deleted'));
			$this->redirect(array('action' => 'index'));
		}
		$this->Session->setFlash(__('Server was not deleted'));
		$this->redirect(array('action' => 'index'));
	}

	/**
	 * Pull one or more events with attributes from a remote instance.
	 * Set $technique to
	 *		full - download everything
	 *		incremental - only new events
	 *		<int>	- specific id of the event to pull
	 */
	public function pull($id = null, $technique=false) {
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		$s = $this->Server->read(null, $id);
		if (!$this->_isSiteAdmin() && !($s['Server']['org_id'] == $this->Auth->user('org_id') && $this->_isAdmin())) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}

		if (false == $this->Server->data['Server']['pull'] && ($technique == 'full' || $technique == 'incremental')) {
			$this->Session->setFlash(__('Pull setting not enabled for this server.'));
			$this->redirect(array('action' => 'index'));
		}
		if (!Configure::read('MISP.background_jobs')) {
			$result = $this->Server->pull($this->Auth->user(), $id, $technique, $s);
			// error codes
			if (isset($result[0]) && is_numeric($result[0])) {
				switch ($result[0]) {
					case '1' :
						$this->Session->setFlash(__('Not authorised. This is either due to an invalid auth key, or due to the sync user not having authentication permissions enabled on the remote server. Another reason could be an incorrect sync server setting.'));
						break;
					case '2' :
						$this->Session->setFlash($result[1]);
						break;
					case '3' :
						throw new NotFoundException('Sorry, this is not yet implemented');
						break;
					case '4' :
						$this->redirect(array('action' => 'index'));
						break;
				}
				$this->redirect($this->referer());
			} else {
				$this->set('successes', $result[0]);
				$this->set('fails', $result[1]);
				$this->set('pulledProposals', $result[2]);
				$this->set('lastpulledid', $result[3]);
			}
		} else {
			$this->loadModel('Job');
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'pull',
					'job_input' => 'Server: ' . $id,
					'status' => 0,
					'retries' => 0,
					'org' => $this->Auth->user('Organisation')['name'],
					'message' => 'Pulling.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
			$process_id = CakeResque::enqueue(
					'default',
					'ServerShell',
					array('pull', $this->Auth->user('id'), $id, $technique, $jobId)
			);
			$this->Job->saveField('process_id', $process_id);
			$this->Session->setFlash('Pull queued for background execution.');
			$this->redirect($this->referer());
		}
	}

	public function push($id = null, $technique=false) {
		$this->Server->id = $id;
		if (!$this->Server->exists()) {
			throw new NotFoundException(__('Invalid server'));
		}
		$s = $this->Server->read(null, $id);
		if (!$this->_isSiteAdmin() && !($s['Server']['org_id'] == $this->Auth->user('org_id') && $this->_isAdmin())) $this->redirect(array('controller' => 'servers', 'action' => 'index'));
		if (!Configure::read('MISP.background_jobs')) {
			$server = $this->Server->read(null, $id);
			App::uses('SyncTool', 'Tools');
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
			$result = $this->Server->push($id, $technique, false, $HttpSocket, $this->Auth->user());
			if ($result === false) {
				$this->Session->setFlash('The remote server is too outdated to initiate a push towards it. Please notify the hosting organisation of the remote instance.');
				$this->redirect(array('action' => 'index'));
			}
			$this->set('successes', $result[0]);
			$this->set('fails', $result[1]);
		} else {
			$this->loadModel('Job');
			$this->Job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'push',
					'job_input' => 'Server: ' . $id,
					'status' => 0,
					'retries' => 0,
					'org' => $this->Auth->user('Organisation')['name'],
					'message' => 'Pushing.',
			);
			$this->Job->save($data);
			$jobId = $this->Job->id;
			$process_id = CakeResque::enqueue(
					'default',
					'ServerShell',
					array('push', $id, $technique, $jobId, $this->Auth->user('id'))
			);
			$this->Job->saveField('process_id', $process_id);
			$this->Session->setFlash('Push queued for background execution.');
			$this->redirect(array('action' => 'index'));
		}
	}

	private function __saveCert($server, $id, $client = false, $delete = false) {
		if ($client) {
			$subm = 'submitted_client_cert';
			$attr = 'client_cert_file';
			$ins  = '_client';
		} else {
			$subm = 'submitted_cert';
			$attr = 'cert_file';
			$ins  = '';
		}
		if (!$delete) {
			$ext = '';
			App::uses('File', 'Utility');
			App::uses('Folder', 'Utility');
			App::uses('FileAccessTool', 'Tools');
			if (!$this->Server->checkFilename($server['Server'][$subm]['name'])) {
				throw new Exception ('Filename not allowed');
			}
			$file = new File($server['Server'][$subm]['name']);
			$ext = $file->ext();
			if (($ext != 'pem') || !$server['Server'][$subm]['size'] > 0) {
				$this->Session->setFlash('Incorrect extension or empty file.');
				$this->redirect(array('action' => 'index'));
			}

			// read pem file data
			$pemData = (new FileAccessTool())->readFromFile($server['Server'][$subm]['tmp_name'], $server['Server'][$subm]['size']);

			$destpath = APP . "files" . DS . "certs" . DS;
			$dir = new Folder(APP . "files" . DS . "certs", true);
			$pemfile = new File($destpath . $id . $ins . '.' . $ext);
			$result = $pemfile->write($pemData);
			$s = $this->Server->read(null, $id);
			$s['Server'][$attr] = $s['Server']['id'] . $ins . '.' . $ext;
			if ($result) $this->Server->save($s);
		} else {
			$s = $this->Server->read(null, $id);
			$s['Server'][$attr] = '';
			$this->Server->save($s);
		}
	}

	public function serverSettingsReloadSetting($setting, $id) {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$pathToSetting = explode('.', $setting);
		if (strpos($setting, 'Plugin.Enrichment') !== false || strpos($setting, 'Plugin.Import') !== false || strpos($setting, 'Plugin.Export') !== false || strpos($setting, 'Plugin.Cortex') !== false) {
			$settingObject = $this->Server->getCurrentServerSettings();
		}
		else $settingObject = $this->Server->serverSettings;
		foreach ($pathToSetting as $key) {
			if (!isset($settingObject[$key])) throw new MethodNotAllowedException();
			$settingObject = $settingObject[$key];
		}
		$result = $this->Server->serverSettingReadSingle($settingObject, $setting, $key);
		$this->set('setting', $result);
		$priorityErrorColours = array(0 => 'red', 1 => 'yellow', 2 => 'green');
		$this->set('priorityErrorColours', $priorityErrorColours);
		$priorities = array(0 => 'Critical', 1 => 'Recommended', 2 => 'Optional', 3 => 'Deprecated');
		$this->set('priorities', $priorities);
		$this->set('k', $id);
		$this->layout = false;

		$subGroup = 'general';
		if ($pathToSetting[0] === 'Plugin') {
			$subGroup = explode('_', $pathToSetting[1])[0];
		}
		$this->set('subGroup', $subGroup);

		$this->render('/Elements/healthElements/settings_row');
	}

	private function __loadLocalOrgs() {
		$this->loadModel('Organisation');
		$local_orgs = $this->Organisation->find('list', array(
				'conditions' => array('local' => 1),
				'recursive' => -1,
				'fields' => array('Organisation.id', 'Organisation.name')
		));
		return array_replace(array(0 => 'No organisation selected.'), $local_orgs);
	}

	public function serverSettings($tab=false) {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if ($this->request->is('Get')) {
			$tabs = array(
					'MISP' => array('count' => 0, 'errors' => 0, 'severity' => 5),
					'Encryption' => array('count' => 0, 'errors' => 0, 'severity' => 5),
					'Proxy' => array('count' => 0, 'errors' => 0, 'severity' => 5),
					'Security' => array('count' => 0, 'errors' => 0, 'severity' => 5),
					'Plugin' => array('count' => 0, 'errors' => 0, 'severity' => 5)
			);
			$writeableErrors = array(0 => 'OK', 1 => 'not found', 2 => 'is not writeable');
			$readableErrors = array(0 => 'OK', 1 => 'not readable');
			$gpgErrors = array(0 => 'OK', 1 => 'FAIL: settings not set', 2 => 'FAIL: Failed to load GPG', 3 => 'FAIL: Issues with the key/passphrase', 4 => 'FAIL: encrypt failed');
			$proxyErrors = array(0 => 'OK', 1 => 'not configured (so not tested)', 2 => 'Getting URL via proxy failed');
			$zmqErrors = array(0 => 'OK', 1 => 'not enabled (so not tested)', 2 => 'Python ZeroMQ library not installed correctly.', 3 => 'ZeroMQ script not running.');
			$stixOperational = array(0 => 'STIX or CyBox or mixbox library not installed correctly', 1 => 'OK');
			$stixVersion = array(0 => 'Incorrect STIX version installed, found $current, expecting $expected', 1 => 'OK');
			$cyboxVersion = array(0 => 'Incorrect CyBox version installed, found $current, expecting $expected', 1 => 'OK');
			$mixboxVersion = array(0 => 'Incorrect mixbox version installed, found $current, expecting $expected', 1 => 'OK');
			$sessionErrors = array(0 => 'OK', 1 => 'High', 2 => 'Alternative setting used', 3 => 'Test failed');
			$moduleErrors = array(0 => 'OK', 1 => 'System not enabled', 2 => 'No modules found');

			$finalSettings = $this->Server->serverSettingsRead();
			$issues = array(
				'errors' => array(
						0 => array(
								'value' => 0,
								'description' => 'MISP will not operate correctly or will be unsecure until these issues are resolved.'
						),
						1 => array(
								'value' => 0,
								'description' => 'Some of the features of MISP cannot be utilised until these issues are resolved.'
						),
						2 => array(
								'value' => 0,
								'description' => 'There are some optional tweaks that could be done to improve the looks of your MISP instance.'
						),
				),
				'deprecated' => array(),
				'overallHealth' => 3,
			);
			$dumpResults = array();
			$tempArray = array();
			foreach ($finalSettings as $k => $result) {
				if ($result['level'] == 3) $issues['deprecated']++;
				$tabs[$result['tab']]['count']++;
				if (isset($result['error']) && $result['level'] < 3) {
					$issues['errors'][$result['level']]['value']++;
					if ($result['level'] < $issues['overallHealth']) $issues['overallHealth'] = $result['level'];
					$tabs[$result['tab']]['errors']++;
					if ($result['level'] < $tabs[$result['tab']]['severity']) $tabs[$result['tab']]['severity'] = $result['level'];
				}
				if (isset($result['optionsSource']) && !empty($result['optionsSource'])) {
					$result['options'] = $this->{'__load' . $result['optionsSource']}();
				}
				$dumpResults[] = $result;
				if ($result['tab'] == $tab) {
					if (isset($result['subGroup'])) $tempArray[$result['subGroup']][] = $result;
					else $tempArray['general'][] = $result;
				}
			}
			$finalSettings = $tempArray;
			// Diagnostics portion
			$diagnostic_errors = 0;
			App::uses('File', 'Utility');
			App::uses('Folder', 'Utility');
			$additionalViewVars = array();
			if ($tab == 'files') {
				$files = $this->__manageFiles();
				$this->set('files', $files);
			}
			// Only run this check on the diagnostics tab
			if ($tab == 'diagnostics' || $tab == 'download') {
				$php_ini = php_ini_loaded_file();
				$this->set('php_ini', $php_ini);
				$advanced_attachments = shell_exec('python ' . APP . 'files/scripts/generate_file_objects.py -c');
				try {
					$advanced_attachments = json_decode($advanced_attachments, true);
				} catch (Exception $e) {
					$advanced_attachments = false;
				}
				$this->set('advanced_attachments', $advanced_attachments);
				// check if the current version of MISP is outdated or not
				$version = $this->__checkVersion();
				$this->set('version', $version);
				$gitStatus = $this->Server->getCurrentGitStatus();
				$this->set('branch', $gitStatus['branch']);
				$this->set('commit', $gitStatus['commit']);
				$this->set('latestCommit', $gitStatus['latestCommit']);
				$phpSettings = array(
						'max_execution_time' => array(
							'explanation' => 'The maximum duration that a script can run (does not affect the background workers). A too low number will break long running scripts like comprehensive API exports',
							'recommended' => 300,
							'unit' => false
						),
						'memory_limit' => array(
							'explanation' => 'The maximum memory that PHP can consume. It is recommended to raise this number since certain exports can generate a fair bit of memory usage',
							'recommended' => 512,
							'unit' => 'M'
						),
						'upload_max_filesize' => array(
							'explanation' => 'The maximum size that an uploaded file can be. It is recommended to raise this number to allow for the upload of larger samples',
							'recommended' => 50,
							'unit' => 'M'
						),
						'post_max_size' => array(
							'explanation' => 'The maximum size of a POSTed message, this has to be at least the same size as the upload_max_filesize setting',
							'recommended' => 50,
							'unit' => 'M'
						)

				);

				foreach ($phpSettings as $setting => $settingArray) {
					$phpSettings[$setting]['value'] = ini_get($setting);
					if ($settingArray['unit']) $phpSettings[$setting]['value'] = intval(rtrim($phpSettings[$setting]['value'], $phpSettings[$setting]['unit']));
					else $phpSettings[$setting]['value'] = intval($phpSettings[$setting]['value']);
				}
				$this->set('phpSettings', $phpSettings);

				if ($version && (!$version['upToDate'] || $version['upToDate'] == 'older')) $diagnostic_errors++;

				// check if the STIX and Cybox libraries are working and the correct version using the test script stixtest.py
				$stix = $this->Server->stixDiagnostics($diagnostic_errors, $stixVersion, $cyboxVersion, $mixboxVersion);

				// if GPG is set up in the settings, try to encrypt a test message
				$gpgStatus = $this->Server->gpgDiagnostics($diagnostic_errors);

				// if the message queue pub/sub is enabled, check whether the extension works
				$zmqStatus = $this->Server->zmqDiagnostics($diagnostic_errors);

				// if Proxy is set up in the settings, try to connect to a test URL
				$proxyStatus = $this->Server->proxyDiagnostics($diagnostic_errors);

				$moduleTypes = array('Enrichment', 'Import', 'Export', 'Cortex');
				foreach ($moduleTypes as $type) {
					$moduleStatus[$type] = $this->Server->moduleDiagnostics($diagnostic_errors, $type);
				}

				// check the size of the session table
				$sessionCount = 0;
				$sessionStatus = $this->Server->sessionDiagnostics($diagnostic_errors, $sessionCount);
				$this->set('sessionCount', $sessionCount);

				$additionalViewVars = array('gpgStatus', 'sessionErrors', 'proxyStatus', 'sessionStatus', 'zmqStatus', 'stixVersion', 'cyboxVersion', 'mixboxVersion', 'moduleStatus', 'gpgErrors', 'proxyErrors', 'zmqErrors', 'stixOperational', 'stix', 'moduleErrors', 'moduleTypes');
			}
			// check whether the files are writeable
			$writeableDirs = $this->Server->writeableDirsDiagnostics($diagnostic_errors);
			$writeableFiles = $this->Server->writeableFilesDiagnostics($diagnostic_errors);
			$readableFiles = $this->Server->readableFilesDiagnostics($diagnostic_errors);
			$extensions = $this->Server->extensionDiagnostics();

			// check if the encoding is not set to utf8
			$dbEncodingStatus = $this->Server->databaseEncodingDiagnostics($diagnostic_errors);

			$viewVars = array(
					'diagnostic_errors', 'tabs', 'tab', 'issues', 'finalSettings', 'writeableErrors', 'readableErrors', 'writeableDirs', 'writeableFiles', 'readableFiles', 'extensions', 'dbEncodingStatus'
			);
			$viewVars = array_merge($viewVars, $additionalViewVars);
			foreach ($viewVars as $viewVar) $this->set($viewVar, ${$viewVar});

			$workerIssueCount = 0;
			if (Configure::read('MISP.background_jobs')) {
				$this->set('worker_array', $this->Server->workerDiagnostics($workerIssueCount));
			} else {
				$workerIssueCount = 4;
				$this->set('worker_array', array());
			}
			if ($tab == 'download') {
				foreach ($dumpResults as $key => $dr) {
					unset($dumpResults[$key]['description']);
				}
				$dump = array(
						'version' => $version,
						'phpSettings' => $phpSettings,
						'gpgStatus' => $gpgErrors[$gpgStatus],
						'proxyStatus' => $proxyErrors[$proxyStatus],
						'zmqStatus' => $zmqStatus,
						'stix' => $stix,
						'moduleStatus' => $moduleStatus,
						'writeableDirs' => $writeableDirs,
						'writeableFiles' => $writeableFiles,
						'readableFiles' => $readableFiles,
						'finalSettings' => $dumpResults,
						'extensions' => $extensions
				);
				foreach ($dump['finalSettings'] as $k => $v) {
					if (!empty($v['redacted'])) {
						$dump['finalSettings'][$k]['value'] = '*****';
					}
				}
				$this->response->body(json_encode($dump, JSON_PRETTY_PRINT));
				$this->response->type('json');
				$this->response->download('MISP.report.json');
				return $this->response;
			}

			$priorities = array(0 => 'Critical', 1 => 'Recommended', 2 => 'Optional', 3 => 'Deprecated');
			$this->set('priorities', $priorities);
			$this->set('workerIssueCount', $workerIssueCount);
			$priorityErrorColours = array(0 => 'red', 1 => 'yellow', 2 => 'green');
			$this->set('priorityErrorColours', $priorityErrorColours);
			$this->set('phpversion', phpversion());
			$this->set('phpmin', $this->phpmin);
			$this->set('phprec', $this->phprec);
		}
	}

	public function startWorker($type) {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
		$validTypes = array('default', 'email', 'scheduler', 'cache', 'prio');
		if (!in_array($type, $validTypes)) throw new MethodNotAllowedException('Invalid worker type.');
		$prepend = '';
		if (Configure::read('MISP.rh_shell_fix')) $prepend = 'export PATH=$PATH:"/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin"; ';
		if ($type != 'scheduler') shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque start --interval 5 --queue ' . $type .' > /dev/null 2>&1 &');
		else shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque startscheduler -i 5 > /dev/null 2>&1 &');
		$this->redirect('/servers/serverSettings/workers');
	}

	public function stopWorker($pid) {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
		$this->Server->killWorker($pid, $this->Auth->user());
		$this->redirect('/servers/serverSettings/workers');
	}

	private function __checkVersion() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		App::uses('SyncTool', 'Tools');
		$syncTool = new SyncTool();
		try {
			$HttpSocket = $syncTool->setupHttpSocket();
			$response = $HttpSocket->get('https://api.github.com/repos/MISP/MISP/tags');
			$tags = $response->body;
		} catch (Exception $e) {
			return false;
		}
		if ($response->isOK() && !empty($tags)) {
			$json_decoded_tags = json_decode($tags);

			// find the latest version tag in the v[major].[minor].[hotfix] format
			for ($i = 0; $i < count($json_decoded_tags); $i++) {
				if (preg_match('/^v[0-9]+\.[0-9]+\.[0-9]+$/', $json_decoded_tags[$i]->name)) break;
			}
			return $this->Server->checkVersion($json_decoded_tags[$i]->name);
		} else {
			return false;
		}
	}

	public function serverSettingsEdit($setting, $id = false, $forceSave = false) {
		// invalidate config.php from php opcode cache
		if (function_exists('opcache_reset')) opcache_reset();

		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if (!isset($setting) || !isset($id)) throw new MethodNotAllowedException();
		$this->set('id', $id);
		if (strpos($setting, 'Plugin.Enrichment') !== false || strpos($setting, 'Plugin.Import') !== false || strpos($setting, 'Plugin.Export') !== false || strpos($setting, 'Plugin.Cortex') !== false) {
			$serverSettings = $this->Server->getCurrentServerSettings();
		}
		else $serverSettings = $this->Server->serverSettings;
		$relevantSettings = (array_intersect_key(Configure::read(), $serverSettings));
		$found = null;
		foreach ($serverSettings as $k => $s) {
			if (isset($s['branch'])) {
				foreach ($s as $ek => $es) {
					if ($ek != 'branch') {
						if ($setting == $k . '.' . $ek) {
							$found = $es;
							continue 2;
						}
					}
				}
			} else {
				if ($setting == $k) {
					$found = $s;
					continue;
				}
			}
		}
		if ($this->request->is('get')) {
			if ($found != null) {
				$value = Configure::read($setting);
				if ($value) $found['value'] = $value;
				$found['setting'] = $setting;
			}
			if (isset($found['optionsSource']) && !empty($found['optionsSource'])) {
				$found['options'] = $this->{'__load' . $found['optionsSource']}();
			}
			$subGroup = 'general';
			$subGroup = explode('.', $setting);
			if ($subGroup[0] === 'Plugin') {
				$subGroup = explode('_', $subGroup[1])[0];
			} else {
				$subGroup = 'general';
			}
			if ($this->_isRest()) {
				return $this->RestResponse->viewData(array($setting => $found['value']));
			} else {
				$this->set('subGroup', $subGroup);
				$this->set('setting', $found);
				$this->render('ajax/server_settings_edit');
			}

		}
		if ($this->request->is('post')) {
			if (!isset($this->request->data['Server'])) $this->request->data = array('Server' => $this->request->data);
			if (!isset($this->request->data['Server']['value'])) {
				if ($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, 'Invalid input. Expected: {"value": "new_setting"}', $this->response->type());
				}
			}
			if (trim($this->request->data['Server']['value']) === '*****') {
				if ($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, 'No change.', $this->response->type());
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'No change.')), 'status'=>200, 'type' => 'json'));
				}
			}
			$this->autoRender = false;
			$this->loadModel('Log');
			if (!is_writeable(APP . 'Config/config.php')) {
				$this->Log->create();
				$result = $this->Log->save(array(
						'org' => $this->Auth->user('Organisation')['name'],
						'model' => 'Server',
						'model_id' => 0,
						'email' => $this->Auth->user('email'),
						'action' => 'serverSettingsEdit',
						'user_id' => $this->Auth->user('id'),
						'title' => 'Server setting issue',
						'change' => 'There was an issue witch changing ' . $setting . ' to ' . $this->request->data['Server']['value']  . '. The error message returned is: app/Config.config.php is not writeable to the apache user. No changes were made.',
				));
				if ($this->_isRest()) {
					return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, 'app/Config.config.php is not writeable to the apache user.', $this->response->type());
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'app/Config.config.php is not writeable to the apache user.')), 'status'=>200, 'type' => 'json'));
				}
			}

			if (isset($found['beforeHook'])) {
				$beforeResult = call_user_func_array(array($this->Server, $found['beforeHook']), array($setting, $this->request->data['Server']['value']));
				if ($beforeResult !== true) {
					$this->Log->create();
					$result = $this->Log->save(array(
							'org' => $this->Auth->user('Organisation')['name'],
							'model' => 'Server',
							'model_id' => 0,
							'email' => $this->Auth->user('email'),
							'action' => 'serverSettingsEdit',
							'user_id' => $this->Auth->user('id'),
							'title' => 'Server setting issue',
							'change' => 'There was an issue witch changing ' . $setting . ' to ' . $this->request->data['Server']['value']  . '. The error message returned is: ' . $beforeResult . 'No changes were made.',
					));
					if ($this->_isRest) {
						return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, $beforeResult, $this->response->type());
					} else {
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $beforeResult)), 'status'=>200, 'type' => 'json'));
					}
				}
			}
			$this->request->data['Server']['value'] = trim($this->request->data['Server']['value']);
			if ($found['type'] == 'boolean') {
				$this->request->data['Server']['value'] = ($this->request->data['Server']['value'] ? true : false);
			}
			if ($found['type'] == 'numeric') {
				$this->request->data['Server']['value'] = intval($this->request->data['Server']['value']);
			}
			if  (!empty($leafValue['test'])) {
				$testResult = $this->Server->{$found['test']}($this->request->data['Server']['value']);
			} else  {
				$testResult = true;  # No test defined for this setting: cannot fail
			}
			if (!$forceSave && $testResult !== true) {
				if ($testResult === false) $errorMessage = $found['errorMessage'];
				else $errorMessage = $testResult;
				if ($this->_isRest) {
					return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, $errorMessage, $this->response->type());
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $errorMessage)), 'status'=>200, 'type' => 'json'));
				}
			} else {
				$oldValue = Configure::read($setting);
				$this->Server->serverSettingsSaveValue($setting, $this->request->data['Server']['value']);
				$this->Log->create();
				$result = $this->Log->save(array(
						'org' => $this->Auth->user('Organisation')['name'],
						'model' => 'Server',
						'model_id' => 0,
						'email' => $this->Auth->user('email'),
						'action' => 'serverSettingsEdit',
						'user_id' => $this->Auth->user('id'),
						'title' => 'Server setting changed',
						'change' => $setting . ' (' . $oldValue . ') => (' . $this->request->data['Server']['value'] . ')',
				));
				// execute after hook
				if (isset($found['afterHook'])) {
					$afterResult = call_user_func_array(array($this->Server, $found['afterHook']), array($setting, $this->request->data['Server']['value']));
					if ($afterResult !== true) {
						$this->Log->create();
						$result = $this->Log->save(array(
								'org' => $this->Auth->user('Organisation')['name'],
								'model' => 'Server',
								'model_id' => 0,
								'email' => $this->Auth->user('email'),
								'action' => 'serverSettingsEdit',
								'user_id' => $this->Auth->user('id'),
								'title' => 'Server setting issue',
								'change' => 'There was an issue after setting a new setting. The error message returned is: ' . $afterResult,
						));
						if ($this->_isRest) {
							return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, $afterResult, $this->response->type());
						} else {
							return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $afterResult)), 'status'=>200, 'type' => 'json'));
						}
					}
				}
				if ($this->_isRest) {
					return $this->RestResponse->saveSuccessResponse('Servers', 'serverSettingsEdit', false, $this->response->type(), 'Field updated');
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Field updated.')), 'status'=>200, 'type' => 'json'));
				}
			}
		}
	}

	public function restartWorkers() {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
		$this->Server->workerRemoveDead($this->Auth->user());
		$prepend = '';
		if (Configure::read('MISP.rh_shell_fix')) {
			$prepend = 'export PATH=$PATH:"/opt/rh/rh-php56/root/usr/bin:/opt/rh/rh-php56/root/usr/sbin"; ';
			if (Configure::read('MISP.rh_shell_fix_path')) {
				if ($this->Server->testForPath(Configure::read('MISP.rh_shell_fix_path'))) $prepend = Configure::read('MISP.rh_shell_fix_path');
			}
		}
		shell_exec($prepend . APP . 'Console' . DS . 'worker' . DS . 'start.sh > /dev/null 2>&1 &');
		$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'workers'));
	}

	private function __manageFiles() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$files = $this->Server->grabFiles();
		return $files;
	}

	public function deleteFile($type, $filename) {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if ($this->request->is('post')) {
			$validItems = $this->Server->getFileRules();
			App::uses('File', 'Utility');
			$existingFile = new File($validItems[$type]['path'] . DS . $filename);
			if (!$existingFile->exists()) {
				$this->Session->setFlash(__('File not found.', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'files'));
			}
			if ($existingFile->delete()) {
				$this->Session->setFlash('File deleted.');
			} else {
				$this->Session->setFlash(__('File could not be deleted.', true), 'default', array(), 'error');
			}
			$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'files'));
		} else {
			throw new MethodNotAllowedException('This action expects a POST request.');
		}
	}

	public function uploadFile($type) {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException();
		$validItems = $this->Server->getFileRules();

		// Check if there were problems with the file upload
		// only keep the last part of the filename, this should prevent directory attacks
		$filename = basename($this->request->data['Server']['file']['name']);
		if (!preg_match("/" . $validItems[$type]['regex'] . "/", $filename)) {
			$this->Session->setFlash(__($validItems[$type]['regex_error'], true), 'default', array(), 'error');
			$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'files'));
		}
		if (empty($this->request->data['Server']['file']['tmp_name']) || !is_uploaded_file($this->request->data['Server']['file']['tmp_name'])) {
			$this->Session->setFlash(__('Upload failed.', true), 'default', array(), 'error');
			$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'files'));
		}

		// check if the file already exists
		App::uses('File', 'Utility');
		$existingFile = new File($validItems[$type]['path'] . DS . $filename);
		if ($existingFile->exists()) {
			$this->Session->setFlash(__('File already exists. If you would like to replace it, remove the old one first.', true), 'default', array(), 'error');
			$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'files'));
		}

		$result = move_uploaded_file($this->request->data['Server']['file']['tmp_name'], $validItems[$type]['path'] . DS . $filename);
		if ($result) {
			$this->Session->setFlash('File uploaded.');
		} else {
			$this->Session->setFlash(__('Upload failed.', true), 'default', array(), 'error');
		}
		$this->redirect(array('controller' => 'servers', 'action' => 'serverSettings', 'files'));
	}

	public function fetchServersForSG($idList = '{}') {
		$id_exclusion_list = json_decode($idList, true);
		$temp = $this->Server->find('all', array(
				'conditions' => array(
						'id !=' => $id_exclusion_list,
				),
				'recursive' => -1,
				'fields' => array('id', 'name', 'url')
		));
		$servers = array();
		foreach ($temp as $server) {
			$servers[] = array('id' => $server['Server']['id'], 'name' => $server['Server']['name'], 'url' => $server['Server']['url']);
		}
		$this->layout = false;
		$this->autoRender = false;
		$this->set('servers', $servers);
		$this->render('ajax/fetch_servers_for_sg');
	}

	public function postTest() {
		if ($this->request->is('post')) {
			// Fix for PHP-FPM / Nginx / etc
			// Fix via https://www.popmartian.com/tipsntricks/2015/07/14/howto-use-php-getallheaders-under-fastcgi-php-fpm-nginx-etc/
			if (!function_exists('getallheaders')) {
				$headers = [];
				foreach ($_SERVER as $name => $value) {
				    if (substr($name, 0, 5) == 'HTTP_') {
				        $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
				    }
				}
			} else {
				$headers = getallheaders();
			}
			$result = array();
			$result['body'] = $this->request->data;
			$result['headers']['Content-type'] = isset($headers['Content-type']) ? $headers['Content-type'] : 0;
			$result['headers']['Accept'] = isset($headers['Accept']) ? $headers['Accept'] : 0;
			$result['headers']['Authorization'] = isset($headers['Authorization']) ? 'OK' : 0;
			return new CakeResponse(array('body'=> json_encode($result), 'type' => 'json'));
		} else {
			throw new MethodNotAllowedException('Invalid request, expecting a POST request.');
		}
	}

	public function testConnection($id = false) {
			if (!$this->Auth->user('Role')['perm_sync'] && !$this->Auth->user('Role')['perm_site_admin']) throw new MethodNotAllowedException('You don\'t have permission to do that.');
			$this->Server->id = $id;
			if (!$this->Server->exists()) {
				throw new NotFoundException(__('Invalid server'));
			}
			$result = $this->Server->runConnectionTest($id);
			if ($result['status'] == 1) {
				$version = json_decode($result['message'], true);
				if (isset($version['version']) && preg_match('/^[0-9]+\.+[0-9]+\.[0-9]+$/', $version['version'])) {
					App::uses('Folder', 'Utility');
					$file = new File(ROOT . DS . 'VERSION.json', true);
					$local_version = json_decode($file->read(), true);
					$file->close();
					$version = explode('.', $version['version']);
					$mismatch = false;
					$newer = false;
					$parts = array('major', 'minor', 'hotfix');
					if ($version[0] == 2 && $version[1] == 4 && $version[2] > 68) {
						$post = $this->Server->runPOSTTest($id);
					}
					$testPost = false;
					foreach ($parts as $k => $v) {
						if (!$mismatch) {
							if ($version[$k] > $local_version[$v]) {
								$mismatch = $v;
								$newer = 'remote';
							} else if ($version[$k] < $local_version[$v]) {
								$mismatch = $v;
								$newer = 'local';
							}
						}
					}
					if (!isset($version['perm_sync'])) {
						if (!$this->Server->checkLegacyServerSyncPrivilege($id)) {
							$result['status'] = 7;
							return new CakeResponse(array('body'=> json_encode($result), 'type' => 'json'));
						}
					} else {
						if (!$version['perm_sync']) {
							$result['status'] = 7;
							return new CakeResponse(array('body'=> json_encode($result), 'type' => 'json'));
						}
					}
					return new CakeResponse(
						array(
						'body'=> json_encode(
							array(
								'status' => 1,
								'local_version' => implode('.', $local_version),
								'version' => implode('.', $version),
								'mismatch' => $mismatch,
								'newer' => $newer,
								'post' => isset($post) ? $post : 'too old'
								)
							),
							'type' => 'json'
						)
					);
				} else {
					$result['status'] = 3;
				}
			}
			return new CakeResponse(array('body'=> json_encode($result), 'type' => 'json'));
	}

	public function startZeroMQServer() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$pubSubTool = $this->Server->getPubSubTool();
		$result = $pubSubTool->restartServer();
		if ($result === true) return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'ZeroMQ server successfully started.')), 'status'=>200, 'type' => 'json'));
		else return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $result)), 'status'=>200, 'type' => 'json'));
	}

	public function stopZeroMQServer() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$pubSubTool = $this->Server->getPubSubTool();
		$result = $pubSubTool->killService();
		if ($result === true) return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'ZeroMQ server successfully killed.')), 'status'=>200, 'type' => 'json'));
		else return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Could not kill the previous instance of the ZeroMQ script.')), 'status'=>200, 'type' => 'json'));
	}

	public function statusZeroMQServer() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		$pubSubTool = $this->Server->getPubSubTool();
		$result = $pubSubTool->statusCheck();
		if (!empty($result)) {
			$this->set('events', $result['publishCount']);
			$this->set('time', date('Y/m/d H:i:s', $result['timestamp']));
			$this->set('time2', date('Y/m/d H:i:s', $result['timestampSettings']));
		}
		$this->render('ajax/zeromqstatus');
	}

	public function purgeSessions() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if ($this->Server->updateDatabase('cleanSessionTable') == false) {
			$this->Session->setFlash('Could not purge the session table.');
		}
		$this->redirect('/servers/serverSettings/diagnostics');
	}

	public function clearWorkerQueue($worker) {
		if (!$this->_isSiteAdmin() || !$this->request->is('Post') || $this->request->is('ajax')) throw new MethodNotAllowedException();
		$worker_array = array('cache', 'default', 'email', 'prio');
		if (!in_array($worker, $worker_array)) throw new MethodNotAllowedException('Invalid worker');
		$redis = Resque::redis();
		$redis->del('queue:' . $worker);
		$this->Session->setFlash('Queue cleared.');
		$this->redirect($this->referer());
	}

	public function getVersion() {
		if (!$this->userRole['perm_auth']) throw new MethodNotAllowedException('This action requires API access.');
		$versionArray = $this->Server->checkMISPVersion();
		$this->set('response', array('version' => $versionArray['major'] . '.' . $versionArray['minor'] . '.' . $versionArray['hotfix'], 'perm_sync' => $this->userRole['perm_sync']));
		$this->set('_serialize', 'response');
	}

	public function getPyMISPVersion() {
		$this->set('response', array('version' => $this->pyMispVersion));
		$this->set('_serialize', 'response');
	}

	public function getGit() {
		$status = $this->Server->getCurrentGitStatus();
	}

	public function checkout() {
		$result = $this->Server->checkoutMain();
	}

	public function update() {
		if ($this->request->is('post')) {
			$status = $this->Server->getCurrentGitStatus();
			$update = $this->Server->update($status);
			return new CakeResponse(array('body'=> $update, 'type' => 'txt'));
		} else {
			$branch = $this->Server->getCurrentBranch();
			$this->set('branch', $branch);
			$this->render('ajax/update');
		}
	}

	public function getInstanceUUID() {
		return $this->RestResponse->viewData(array('uuid' => Configure::read('MISP.uuid')), $this->response->type());
	}
}
