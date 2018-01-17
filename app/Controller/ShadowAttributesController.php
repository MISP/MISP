<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

class ShadowAttributesController extends AppController {

	public $components = array('Acl', 'Security', 'RequestHandler', 'Email');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,
		);

	public $helpers = array('Js' => array('Jquery'));

	public function beforeFilter() {
		parent::beforeFilter();
		$this->set('title_for_layout', 'Proposals');
		$this->Security->validatePost = true;

		// convert uuid to id if present in the url, and overwrite id field
		if (isset($this->params->query['uuid'])) {
			$params = array(
					'conditions' => array('ShadowAttribute.uuid' => $this->params->query['uuid']),
					'recursive' => 0,
					'fields' => 'ShadowAttribute.id'
					);
			$result = $this->ShadowAttribute->find('first', $params);
			if (isset($result['ShadowAttribute']) && isset($result['ShadowAttribute']['id'])) {
				$id = $result['ShadowAttribute']['id'];
				$this->params->addParams(array('pass' => array($id))); // FIXME find better way to change id variable if uuid is found. params->url and params->here is not modified accordingly now
			}
		}

		// if not admin or own org, check private as well..
		if (!$this->_isSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate,array(
			'conditions' =>
					array('OR' =>
							array(
								'Event.org =' => $this->Auth->user('org_id'),
								'AND' => array(
									'ShadowAttribute.org =' => $this->Auth->user('org_id'),
									'Event.distribution >' => 0,
									Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
								),
							)
			)));
		}
	}

	private function __accept($id) {
		$this->loadModel('Attribute');
		$this->Attribute->Behaviors->detach('SysLogLogable.SysLogLogable');
		$shadow = $this->ShadowAttribute->find(
			'first',
			array(
				'recursive' => -1,
				'conditions' => array(
					'ShadowAttribute.id' => $id,
					'deleted' => 0
				),
			)
		);
		if (empty($shadow)) return array('false' => true, 'errors' => 'Proposal not found or you are not authorised to accept it.');
		$shadow = $shadow['ShadowAttribute'];
		if ($this->ShadowAttribute->typeIsAttachment($shadow['type'])) {
			$encodedFile = $this->ShadowAttribute->base64EncodeAttachment($shadow);
			$shadow['data'] = $encodedFile;
		}
		// If the old_id is set to anything but 0 then we're dealing with a proposed edit to an existing attribute
		if ($shadow['old_id'] != 0) {
			// Find the live attribute by the shadow attribute's uuid, so we can begin editing it
			$this->Attribute->contain = 'Event';
			$activeAttribute = $this->Attribute->findByUuid($shadow['uuid']);

			// Send those away that shouldn't be able to see this
			if (!$this->_isSiteAdmin()) {
				if ($activeAttribute['Event']['orgc_id'] != $this->Auth->user('org_id') || (!$this->userRole['perm_modify'])) {
					if ($this->_isRest()) {
						return array('false' => true, 'errors' => 'Proposal not found or you are not authorised to accept it.');
					} else {
						$this->Session->setFlash('You don\'t have permission to do that');
						$this->redirect(array('controller' => 'events', 'action' => 'view', $shadow['event_id']));
					}
				}
			}
			$date = new DateTime();
			if (isset($shadow['proposal_to_delete']) && $shadow['proposal_to_delete']) {
				$this->Attribute->delete($activeAttribute['Attribute']['id']);
			} else {
				// Update the live attribute with the shadow data
				$fieldsToUpdate = array('value1', 'value2', 'value', 'type', 'category', 'comment', 'to_ids');
				foreach ($fieldsToUpdate as $f) $activeAttribute['Attribute'][$f] = $shadow[$f];
				$activeAttribute['Attribute']['timestamp'] = $date->getTimestamp();
				$this->Attribute->save($activeAttribute['Attribute']);
			}
			$this->ShadowAttribute->setDeleted($id);
			$this->loadModel('Event');
			$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
			$this->Event->recursive = -1;
			// Unpublish the event, accepting a proposal is modifying the event after all. Also, reset the lock.
			$event = $this->Event->read(null, $activeAttribute['Attribute']['event_id']);
			$this->Event->unpublishEvent($activeAttribute['Attribute']['event_id'], true);
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
				'org_id' => $this->Auth->user('org_id'),
				'model' => 'ShadowAttribute',
				'model_id' => $id,
				'email' => $this->Auth->user('email'),
				'action' => 'accept',
				'title' => 'Proposal (' . $shadow['id'] . ') of ' . $shadow['org_id'] . ' to Attribute (' . $shadow['old_id'] . ') of Event (' . $shadow['event_id'] . ') accepted - ' . $shadow['category'] . '/' . $shadow['type'] . ' ' . $shadow['value'],
			));
			return array('saved' => true, 'success' => 'Proposed change accepted.');
		} else {
			// If the old_id is set to 0, then we're dealing with a brand new proposed attribute
			// The idea is to load the event that the new attribute will be attached to, create an attribute to it and set the distribution equal to that of the event
			$toDeleteId = $shadow['id'];
			$this->loadModel('Event');
			$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
			$this->Event->recursive = -1;
			$event = $this->Event->read(null, $shadow['event_id']);

			if (!$this->_isSiteAdmin()) {
				if (($event['Event']['orgc_id'] != $this->Auth->user('org_id')) || (!$this->userRole['perm_modify'])) {
					$this->Session->setFlash('You don\'t have permission to do that');
					$this->redirect(array('controller' => 'events', 'action' => 'index'));
				}
			}
			$shadowForLog = $shadow;
			// Stuff that we won't use in its current form for the attribute
			unset($shadow['email'], $shadow['org_id'], $shadow['id'], $shadow['old_id']);
			$attribute = $shadow;

			// set the distribution equal to that of the event
			$attribute['distribution'] = 5;
			$this->Attribute->create();
			$this->Attribute->save($attribute);
			$this->ShadowAttribute->setDeleted($toDeleteId);

			if ($this->Auth->user('org_id') == $event['Event']['orgc_id']) {
				$this->Event->unpublishEvent($activeAttribute['Attribute']['event_id'], true);
				$event['Event']['proposal_email_lock'] = 0;
			} else {
				$this->Event->unpublishEvent($activeAttribute['Attribute']['event_id']);
			}
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
				'org_id' => $this->Auth->user('org_id'),
				'model' => 'ShadowAttribute',
				'model_id' => $id,
				'email' => $this->Auth->user('email'),
				'action' => 'accept',
				'title' => 'Proposal (' . $shadowForLog['id'] . ') of ' . $shadowForLog['org_id'] . ' to Event(' . $shadowForLog['event_id'] . ') accepted',
				'change' => null,
			));
			return array('saved' => true, 'success' => 'Proposal accepted.');
		}
	}

	// Accept a proposed edit and update the attribute
	public function accept($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$response = $this->__accept($id);
		if ($this->_isRest()) {
			if (isset($response['success'])) {
				$response['check_publish'] = true;
				$this->set('name', $response['success']);
				$this->set('message', $response['success']);
				$this->set('url', '/shadow_attributes/accept/' . $id);
				$this->set('_serialize', array('name', 'message', 'url'));
			} else {
				throw new MethodNotAllowedException($response['errors']);
			}
		} else {
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode($response), 'status'=>200, 'type' => 'json'));
		}
	}

	// If we accept a proposed attachment, then the attachment itself needs to be moved from files/eventId/shadow/shadowId to files/eventId/attributeId
	private function _moveFile($shadowId, $newId, $eventId) {
		$pathOld = APP . "files" . DS . $eventId . DS . "shadow" . DS . $shadowId;
		$pathNew = APP . "files" . DS . $eventId . DS . $newId;
		if (rename($pathOld, $pathNew)) {
			return true;
		} else {
			$this->Session->setFlash(__('Moving of the file that this attachment references failed.', true), 'default', array());
			$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
		}
	}


	private function __discard($id) {
			$sa = $this->ShadowAttribute->find(
				'first',
				array(
					'recursive' => -1,
					'conditions' => array(
						'ShadowAttribute.id' => $id,
						'deleted' => 0
					),
				)
			);
			if (empty($sa)) return false;
			$eventId = $sa['ShadowAttribute']['event_id'];
			$this->loadModel('Event');
			$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
			$this->Event->recursive = -1;
			$this->Event->id = $eventId;
			$this->Event->read();
			// Send those away that shouldn't be able to see this
			if (!$this->_isSiteAdmin()) {
				if ((($this->Event->data['Event']['orgc_id'] != $this->Auth->user('org_id')) && ($this->Auth->user('org_id') != $sa['ShadowAttribute']['org_id'])) || (!$this->userRole['perm_modify'])) {
					return false;
				}
			}
			if ($this->ShadowAttribute->setDeleted($id)) {
				if ($this->Auth->user('org_id') == $this->Event->data['Event']['orgc_id']) {
					$this->ShadowAttribute->setProposalLock($eventId, false);
				}
				$this->Log = ClassRegistry::init('Log');
				$this->Log->create();
				$this->Log->save(array(
						'org_id' => $this->Auth->user('org_id'),
						'model' => 'ShadowAttribute',
						'model_id' => $id,
						'email' => $this->Auth->user('email'),
						'action' => 'discard',
						'title' => 'Proposal (' . $sa['ShadowAttribute']['id'] . ') of ' . $sa['ShadowAttribute']['org_id'] . ' discarded - ' . $sa['ShadowAttribute']['category'] . '/' . $sa['ShadowAttribute']['type'] . ' ' . $sa['ShadowAttribute']['value'],
				));
				return true;
			}
			return false;
	}

	// This method will discard a proposed change. Users that can delete the proposals are the publishing users of the org that created the event and of the ones that created the proposal - in addition to site admins of course
	public function discard($id = null) {
		if ($this->request->is('post')) {
			if ($this->__discard($id)) {
				if ($this->_isRest()) {
					$this->set('name', 'Proposal discarded.');
					$this->set('message', 'Proposal discarded.');
					$this->set('url', '/shadow_attributes/discard/' . $id);
					$this->set('_serialize', array('name', 'message', 'url'));
				} else {
					$this->autoRender = false;
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Proposal discarded.')), 'status'=>200, 'type' => 'json'));
				}
			} else {
				if ($this->_isRest()) {
					throw new MethodNotAllowedException('Could not discard proposal.');
				} else {
					$this->autoRender = false;
					return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Could not discard proposal.')), 'status'=>200, 'type' => 'json'));
				}
			}
		} else {
			if (!$this->request->is('ajax')) {
				throw new MethodNotAllowedException();
			}
			$this->autoRender = false;
			$this->set('id', $id);
			$shadowAttribute = $this->ShadowAttribute->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'event_id'),
			));
			$this->set('event_id', $shadowAttribute['ShadowAttribute']['event_id']);
			$this->render('ajax/shadowAttributeConfirmationForm');
		}
	}

	public function add($eventId) {
		if ($this->request->is('ajax'))	{
			$this->set('ajax', true);
			$this->layout = 'ajax';
		} else {
			$this->set('ajax', false);
		}
		if (empty($eventId)) {
			if (empty($event)) throw new NotFoundException('Invalid Event');
		}
		$event = $this->ShadowAttribute->Event->fetchEvent($this->Auth->user(), array('eventid' => $eventId));
		if (empty($event)) throw new NotFoundException('Invalid Event');
		$event = $event[0];

		if ($this->request->is('post')) {
			if (isset($this->request->data['request'])) $this->request->data = $this->request->data['request'];
			// rearrange the request in case someone didn't RTFM
			$invalidNames = array('Attribute', 'Proposal');
			foreach ($invalidNames as $iN) {
				if (isset($this->request->data[$iN]) && !isset($this->request->data['ShadowAttribute'])) {
					$this->request->data['ShadowAttribute'] = $this->request->data[$iN];
				}
			}
			if (!isset($this->request->data['ShadowAttribute'])) {
				$this->request->data = array('ShadowAttribute' => $this->request->data);
			}
			if ($this->request->is('ajax')) $this->autoRender = false;
			// Give error if someone tried to submit an attribute with type 'attachment' or 'malware-sample'.
			// TODO change behavior attachment options - this is bad ... it should rather by a messagebox or should be filtered out on the view level
			if (isset($this->request->data['ShadowAttribute']['type']) && $this->ShadowAttribute->typeIsAttachment($this->request->data['ShadowAttribute']['type']) && !$this->_isRest()) {
				$this->Session->setFlash(__('Attribute has not been added: attachments are added by "Add attachment" button', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
			}
			$this->request->data['ShadowAttribute']['event_id'] = $eventId;
			//
			// multiple attributes in batch import
			//
			if (!$this->_isRest() && (isset($this->request->data['ShadowAttribute']['batch_import']) && $this->request->data['ShadowAttribute']['batch_import'] == 1)) {
				// make array from value field
				$attributes = explode("\n", $this->request->data['ShadowAttribute']['value']);
				$fails = "";	// will be used to keep a list of the lines that failed or succeeded
				$successes = "";
				// TODO loopholes
				// the value null value thing
				foreach ($attributes as $key => $attribute) {
					$attribute = trim($attribute);
					if (strlen($attribute) == 0)
					continue; // don't do anything for empty lines
					$this->ShadowAttribute->create();
					$this->request->data['ShadowAttribute']['value'] = $attribute; // set the value as the content of the single line
					$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
					$this->request->data['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
					$this->request->data['ShadowAttribute']['event_uuid'] = $event['Event']['uuid'];
					$this->request->data['ShadowAttribute']['event_org_id'] = $event['Event']['org_id'];
					// TODO loopholes
					// there seems to be a loophole in MISP here
					// be it an create and not an update
					$this->ShadowAttribute->id = null;
					if ($this->ShadowAttribute->save($this->request->data)) {
						$successes .= " " . ($key + 1);
					} else {
						$fails .= " " . ($key + 1);
					}
				}
				// we added all the attributes
				if ($this->request->is('ajax')) {
					// handle it if some of them failed!
					if ($fails) {
						$error_message = 'The lines' . $fails . ' could not be saved. Please, try again.';
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $error_message)), 'status' => 200, 'type' => 'json'));
					} else {
						return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200, 'type' => 'json'));
					}
				} else {
					if ($fails) {
						// list the ones that failed
						if (!CakeSession::read('Message.flash')) {
							$this->Session->setFlash(__('The lines' . $fails . ' could not be saved. Please, try again.', true), 'default', array(), 'error');
						} else {
							$existingFlash = CakeSession::read('Message.flash');
							$this->Session->setFlash(__('The lines' . $fails . ' could not be saved. ' . $existingFlash['message'], true), 'default', array(), 'error');
						}
					}
					if ($successes) {
						// list the ones that succeeded
						$emailResult = "";
						if (!$this->ShadowAttribute->sendProposalAlertEmail($eventId) === false) {
							$emailResult = " but nobody from the owner organisation could be notified by e-mail.";
						}
						$this->Session->setFlash(__('The lines' . $successes . ' have been saved' . $emailResult, true));
					}
				}

				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));

			} else {
				//
				// single attribute
				//
				// create the attribute
				$this->ShadowAttribute->create();
				$savedId = $this->ShadowAttribute->getID();
				$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
				$this->request->data['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
				$this->request->data['ShadowAttribute']['event_uuid'] = $event['Event']['uuid'];
				$this->request->data['ShadowAttribute']['event_org_id'] = $event['Event']['org_id'];
				if ($this->ShadowAttribute->save($this->request->data)) {
					// list the ones that succeeded
					$emailResult = "";
					if (!isset($this->request->data['ShadowAttribute']['deleted']) || !$this->request->data['ShadowAttribute']['deleted']) {
						if (!$this->ShadowAttribute->sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id'])) {
							$emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
						}
					}
					// inform the user and redirect
					if ($this->request->is('ajax')) {
						$this->autoRender = false;
						return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Proposal added' . $emailResult)), 'status'=>200, 'type' => 'json'));
					} else if ($this->_isRest()) {
						$sa = $this->ShadowAttribute->find(
							'first',
							array(
								'conditions' => array('ShadowAttribute.id' => $this->ShadowAttribute->id),
								'recursive' => -1,
								'fields' => array('id', 'old_id', 'event_id', 'type', 'category', 'value', 'comment','to_ids', 'uuid', 'event_org_id', 'email', 'deleted', 'timestamp')
							)
						);
						$this->set('ShadowAttribute', $sa['ShadowAttribute']);
						$this->set('_serialize', array('ShadowAttribute'));
					} else {
						$this->Session->setFlash(__('The proposal has been saved'));
						$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
					}
				} else {
					if ($this->request->is('ajax')) {
						$this->autoRender = false;
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $this->ShadowAttribute->validationErrors)), 'status'=>200, 'type' => 'json'));
					} else if ($this->_isRest()) {
						$message = '';
						foreach ($this->ShadowAttribute->validationErrors as $k => $v) {
							$message .= '[' . $k . ']: ' . $v[0] . PHP_EOL;
						}
						throw new NotFoundException('Could not save the proposal. Errors: ' . $message);
					} else {
						if (!CakeSession::read('Message.flash')) {
							$this->Session->setFlash(__('The attribute could not be saved. Please, try again.'));
						}
					}
				}
			}
		} else {
			// set the event_id in the form
			$this->request->data['ShadowAttribute']['event_id'] = $eventId;
		}
		$this->set('event_id', $eventId);
		// combobox for types
		$types = array_keys($this->ShadowAttribute->typeDefinitions);
		foreach ($types as $key => $value) {
			if (in_array($value, array('malware-sample', 'attachment'))) {
				unset($types[$key]);
			}
		}
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobox for categories
		$categories = array_keys($this->ShadowAttribute->Event->Attribute->categoryDefinitions);
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', compact('categories'));
		foreach ($this->ShadowAttribute->Event->Attribute->categoryDefinitions as $key => $value) {
			$info['category'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($this->ShadowAttribute->Event->Attribute->typeDefinitions as $key => $value) {
			$info['type'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		$this->set('info', $info);
		$this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);
	}

	public function download($id = null) {
		$this->ShadowAttribute->id = $id;
		if (!$this->ShadowAttribute->exists()) {
			throw new NotFoundException(__('Invalid Proposal'));
		}
		$sa = $this->ShadowAttribute->find('first', array(
			'recursive' => -1,
			'contain' => array('Event' => array('fields' => array('Event.org_id', 'Event.distribution', 'Event.id'))),
			'conditions' => array('ShadowAttribute.id' => $id)
		));
		if (!$this->ShadowAttribute->Event->checkIfAuthorised($this->Auth->user(), $sa['Event']['id'])) throw new UnauthorizedException('You do not have the permission to view this event.');
		$this->__downloadAttachment($sa['ShadowAttribute']);
	}

	private function __downloadAttachment($shadowAttribute) {
		$path = "files" . DS . 'shadow' . DS . $shadowAttribute['event_id'] . DS;
		$file = $shadowAttribute['id'];
		if ('attachment' == $shadowAttribute['type']) {
			$filename = $shadowAttribute['value'];
			$fileExt = pathinfo($filename, PATHINFO_EXTENSION);
			$filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
		} else if ('malware-sample' == $shadowAttribute['type']) {
			$filenameHash = explode('|', $shadowAttribute['value']);
			$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
			$fileExt = "zip";
		} else {
			throw new NotFoundException(__('Proposal not an attachment or malware-sample'));
		}
		$this->autoRender = false;
		$this->response->type($fileExt);
		$this->response->file($path . $file, array('download' => true, 'name' => $filename . '.' . $fileExt));
	}

	public function add_attachment($eventId = null) {
		$event = $this->ShadowAttribute->Event->fetchEvent($this->Auth->user(), array('eventid' => $eventId));
		if (empty($event)) throw new NotFoundException('Invalid Event');
		$event = $event[0];

		if ($this->request->is('post')) {
			// Check if there were problems with the file upload
			// only keep the last part of the filename, this should prevent directory attacks
			$hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
			$filename = basename($this->request->data['ShadowAttribute']['value']['name']);
			$tmpfile = new File($this->request->data['ShadowAttribute']['value']['tmp_name']);
			if ((isset($this->request->data['ShadowAttribute']['value']['error']) && $this->request->data['ShadowAttribute']['value']['error'] == 0) ||
			(!empty( $this->request->data['ShadowAttribute']['value']['tmp_name']) && $this->request->data['ShadowAttribute']['value']['tmp_name'] != 'none')
			) {
				if (!is_uploaded_file($tmpfile->path))
					throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
			} else {
				$this->Session->setFlash(__('There was a problem to upload the file.', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
			}

			$fails = array();
			$completeFail = false;

			if ($this->request->data['ShadowAttribute']['malware']) {
				$result = $this->ShadowAttribute->Event->Attribute->handleMaliciousBase64($this->request->data['ShadowAttribute']['event_id'], $filename, base64_encode($tmpfile->read()), array_keys($hashes));
				if (!$result['success']) {
					$this->Session->setFlash(__('There was a problem to upload the file.', true), 'default', array(), 'error');
					$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
				}
				foreach ($hashes as $hash => $typeName) {
					if (!$result[$hash]) continue;
					$shadowAttribute = array(
							'ShadowAttribute' => array(
									'value' => $filename . '|' . $result[$hash],
									'category' => $this->request->data['ShadowAttribute']['category'],
									'type' => $typeName,
									'event_id' => $this->request->data['ShadowAttribute']['event_id'],
									'comment' => $this->request->data['ShadowAttribute']['comment'],
									'to_ids' => 1,
									'email' => $this->Auth->user('email'),
									'org_id' => $this->Auth->user('org_id'),
									'event_uuid' => $event['Event']['uuid'],
									'event_org_id' => $event['Event']['orgc_id'],
							)
					);
					if ($hash == 'md5') $shadowAttribute['ShadowAttribute']['data'] = $result['data'];
					$this->ShadowAttribute->create();
					$r = $this->ShadowAttribute->save($shadowAttribute);
					if ($r == false) $fails[] = array($typeName);
					if (count($fails) == count($hashes)) $completeFail = true;
				}
			} else {
				$shadowAttribute = array(
						'ShadowAttribute' => array(
								'value' => $filename,
								'category' => $this->request->data['ShadowAttribute']['category'],
								'type' => 'attachment',
								'event_id' => $this->request->data['ShadowAttribute']['event_id'],
								'comment' => $this->request->data['ShadowAttribute']['comment'],
								'data' => base64_encode($tmpfile->read()),
								'to_ids' => 0,
								'email' => $this->Auth->user('email'),
								'org_id' => $this->Auth->user('org_id'),
								'event_uuid' => $event['Event']['uuid'],
								'event_org_id' => $event['Event']['orgc_id'],
						)
				);
				$this->ShadowAttribute->create();
				$r = $this->ShadowAttribute->save($shadowAttribute);
				if ($r == false) {
					$fails[] = array('attachment');
					$completeFail = true;
				}
			}
			if (!$completeFail) {
				if (empty($fails)) {
					$this->Session->setFlash(__('The attachment has been uploaded'));
				} else {
					$this->Session->setFlash(__('The attachment has been uploaded, but some of the proposals could not be created. The failed proposals are: ' . implode(', ', $fails)));
				}
			} else {
				$this->Session->setFlash(__('The attachment could not be saved, please contact your administrator.'));
			}
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));

		} else {
			// set the event_id in the form
			$this->request->data['ShadowAttribute']['event_id'] = $eventId;
		}

		// combobox for categories
		$categories = array_keys($this->ShadowAttribute->Event->Attribute->categoryDefinitions);
		$categories = $this->_arrayToValuesIndexArray($categories);
		// just get them with attachments..
		$selectedCategories = array();
		foreach ($categories as $category) {
			if (isset($this->ShadowAttribute->categoryDefinitions[$category])) {
				$types = $this->ShadowAttribute->categoryDefinitions[$category]['types'];
				$alreadySet = false;
				foreach ($types as $type) {
					if ($this->ShadowAttribute->typeIsAttachment($type) && !$alreadySet) {
						// add to the whole..
						$selectedCategories[] = $category;
						$alreadySet = true;
					}
				}
			}
		}
		$categories = $this->_arrayToValuesIndexArray($selectedCategories);
		$this->set('categories',$categories);
		foreach ($this->ShadowAttribute->Event->Attribute->categoryDefinitions as $key => $value) {
			$info['category'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($this->ShadowAttribute->Event->Attribute->typeDefinitions as $key => $value) {
			$info['type'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		$this->set('info', $info);
		$this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);

		$this->set('zippedDefinitions', $this->ShadowAttribute->zippedDefinitions);
		$this->set('uploadDefinitions', $this->ShadowAttribute->uploadDefinitions);
	}

	// Propose an edit to an attribute
	// Fields that can be used to edit an attribute when using the API:
	// type, category, value, comment, to_ids
	// if any of these fields is set, it will create a proposal
	public function edit($id = null) {
		$existingAttribute = $this->ShadowAttribute->Event->Attribute->fetchAttributes($this->Auth->user(), array(
				'contain' => array('Event' => array('fields' => array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.distribution', 'Event.uuid'))),
				'conditions' => array('Attribute.id' => $id),
				'flatten' => 1
		));
		if (empty($existingAttribute)) throw new MethodNotAllowedException('Invalid Attribute.');
		$existingAttribute = $existingAttribute[0];

		// Check if the attribute is an attachment, if yes, block the type and the value fields from being edited.
		if ('attachment' == $existingAttribute['Attribute']['type'] || 'malware-sample' == $existingAttribute['Attribute']['type'] ) {
			$this->set('attachment', true);
			$attachment = true;
		} else {
			$this->set('attachment', false);
			$attachment = false;
		}

		if ($this->request->is('post') || $this->request->is('put')) {
			if (isset($this->request->data['request'])) $this->request->data = $this->request->data['request'];
			// rearrange the request in case someone didn't RTFM
			$invalidNames = array('Attribute', 'Proposal');
			foreach ($invalidNames as $iN) if (isset($this->request->data[$iN]) && !isset($this->request->data['ShadowAttribute'])) $this->request->data['ShadowAttribute'] = $this->request->data[$iN];
			if ($attachment) {
				$fields = array(
						'static' => array('old_id' => 'Attribute.id', 'uuid' => 'Attribute.uuid', 'event_id' => 'Attribute.event_id', 'event_uuid' => 'Event.uuid', 'event_org_id' => 'Event.orgc_id', 'category' => 'Attribute.category', 'type' => 'Attribute.type'),
						'optional' => array('value', 'to_ids', 'comment')
				);
			} else {
				$fields = array(
						'static' => array('old_id' => 'Attribute.id', 'uuid' => 'Attribute.uuid', 'event_id' => 'Attribute.event_id', 'event_uuid' => 'Event.uuid', 'event_org_id' => 'Event.orgc_id'),
						'optional' => array('category', 'type', 'value', 'to_ids', 'comment')
				);
				if ($existingAttribute['Attribute']['object_id']) {
					unset($fields['optional']['type']);
					$fields['static']['type'] = 'Attribute.type';
				}
			}
			foreach ($fields['static'] as $k => $v) {
				$v = explode('.', $v);
				$this->request->data['ShadowAttribute'][$k] = $existingAttribute[$v[0]][$v[1]];
			}
			$validChangeMade = false;
			foreach ($fields['optional'] as $v) {
				if (!isset($this->request->data['ShadowAttribute'][$v])) {
					$this->request->data['ShadowAttribute'][$v] = $existingAttribute['Attribute'][$v];
				} else {
					$validChangeMade = true;
				}
			}
			if (!$validChangeMade) throw new MethodNotAllowedException('Invalid input.');
			$this->request->data['ShadowAttribute']['org_id'] =  $this->Auth->user('org_id');
			$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
			if ($this->ShadowAttribute->save($this->request->data)) {
				$emailResult = "";
				if (!isset($this->request->data['ShadowAttribute']['deleted']) || !$this->request->data['ShadowAttribute']['deleted']) {
					if (!$this->ShadowAttribute->sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id'])) $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
				}
				if ($this->_isRest()) {
					$sa = $this->ShadowAttribute->find(
							'first',
							array(
									'conditions' => array('ShadowAttribute.id' => $this->ShadowAttribute->id),
									'recursive' => -1,
									'fields' => array('id', 'old_id', 'event_id', 'type', 'category', 'value', 'comment','to_ids', 'uuid', 'event_org_id', 'email', 'deleted', 'timestamp')
							)
					);
					$this->set('ShadowAttribute', $sa['ShadowAttribute']);
					$this->set('_serialize', array('ShadowAttribute'));
				} else {
					$this->Session->setFlash(__('The proposed Attribute has been saved' . $emailResult));
					$this->redirect(array('controller' => 'events', 'action' => 'view', $existingAttribute['Attribute']['event_id']));
				}
			} else {
				if ($this->_isRest()) {
					$message = '';
					foreach ($this->ShadowAttribute->validationErrors as $k => $v) {
						$message .= '[' . $k . ']: ' . $v[0] . PHP_EOL;
					}
					throw new NotFoundException('Could not save the proposal. Errors: ' . $message);
				} else {
					$this->Session->setFlash(__('The ShadowAttribute could not be saved. Please, try again.'));
				}
			}
		} else {
			// Read the attribute that we're about to edit
			$this->ShadowAttribute->create();
			$this->request->data['ShadowAttribute'] = $existingAttribute['Attribute'];
			unset($this->request->data['ShadowAttribute']['id']);
		}

		// combobox for types
		$types = array_keys($this->ShadowAttribute->typeDefinitions);
		foreach ($types as $key => $value) {
			if (in_array($value, array('malware-sample', 'attachment'))) {
				unset($types[$key]);
			}
		}
		if ($existingAttribute['Attribute']['object_id']) {
			$this->set('objectAttribute', true);
		} else {
			$this->set('objectAttribute', false);
		}
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobox for categories
		$categories = $this->_arrayToValuesIndexArray(array_keys($this->ShadowAttribute->Event->Attribute->categoryDefinitions));
		$categories = $this->_arrayToValuesIndexArray($categories);
		foreach ($this->ShadowAttribute->Event->Attribute->categoryDefinitions as $key => $value) {
			$info['category'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($this->ShadowAttribute->Event->Attribute->typeDefinitions as $key => $value) {
			$info['type'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		$categoryDefinitions = $this->ShadowAttribute->Event->Attribute->categoryDefinitions;
		if ($existingAttribute['Attribute']['object_id']) {
			foreach ($categoryDefinitions as $k => $v) {
				if (!in_array($existingAttribute['Attribute']['type'], $v['types'])) {
					unset($categoryDefinitions[$k]);
				}
			}
			foreach ($categories as $k => $v) {
				if (!isset($categoryDefinitions[$k])) {
					unset($categories[$k]);
				}
			}
		}
		$this->set('categories', $categories);
		$this->set('info', $info);
		$this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->ShadowAttribute->Event->Attribute->categoryDefinitions);
	}

	public function delete($id) {
		if (strlen($id) == 36) {
			$this->ShadowAttribute->Event->recursive = -1;
			$temp = $this->ShadowAttribute->Event->Attribute->find('first', array('recursive' => -1, 'conditions' => array('Attribute.uuid' => $id), 'fields' => array('id')));
			if ($temp == null) throw new NotFoundException('Invalid attribute');
			$id = $temp['Attribute']['id'];
		}

		$existingAttribute = $this->ShadowAttribute->Event->Attribute->find(
			'first',
			array(
				'recursive' => -1,
				'conditions' => array(
					'Attribute.id' => $id
				),
				'contain' => array('Event' => array('fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id')))
		));

		if ($this->request->is('post')) {
			if (empty($existingAttribute)) return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Invalid Attribute.')), 'status'=>200, 'type' => 'json'));
			$this->ShadowAttribute->create();
			$sa = array(
					'old_id' => $existingAttribute['Attribute']['id'],
					'uuid' => $existingAttribute['Attribute']['uuid'],
					'event_id' => $existingAttribute['Event']['id'],
					'event_uuid' => $existingAttribute['Event']['uuid'],
					'event_org_id' => $existingAttribute['Event']['orgc_id'],
					'category' => $existingAttribute['Attribute']['category'],
					'type' => $existingAttribute['Attribute']['type'],
					'to_ids' => $existingAttribute['Attribute']['to_ids'],
					'value' => $existingAttribute['Attribute']['value'],
					'email' => $this->Auth->user('email'),
					'org_id' => $this->Auth->user('org_id'),
					'proposal_to_delete' => true,
			);
			if ($this->ShadowAttribute->save($sa)) {
				$emailResult = "";
				if (!$this->ShadowAttribute->sendProposalAlertEmail($existingAttribute['Event']['id'])) $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'The proposal to delete the attribute has been saved' . $emailResult)), 'status'=>200, 'type' => 'json'));
			} else {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Could not create proposal.')), 'status'=>200, 'type' => 'json'));
			}
		} else {
			if (empty($existingAttribute)) throw new NotFoundException(__('Invalid Attribute'));
			$this->set('id', $id);
			$this->set('event_id', $existingAttribute['Attribute']['event_id']);
			$this->render('ajax/deletionProposalConfirmationForm');
		}
	}

	public function view($id) {
		$distConditions = array();
		if (!$this->_isSiteAdmin()) {
			$distConditions = array(
					'OR' => array(
							'Event.distribution >' => 0,
							'Event.org_id' => $this->Auth->user('org_id'),
							'Event.orgc_id' => $this->Auth->user('org_id'),
					),
			);
		}
		$sa = $this->ShadowAttribute->find('first', array(
				'recursive' => -1,
				'contain' => 'Event',
				'fields' => array(
					'ShadowAttribute.id', 'ShadowAttribute.old_id', 'ShadowAttribute.event_id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.uuid', 'ShadowAttribute.to_ids', 'ShadowAttribute.value', 'ShadowAttribute.comment', 'ShadowAttribute.org_id',
					'Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.distribution', 'Event.uuid'
				),
				'conditions' => array('AND' => array('ShadowAttribute.id' => $id, $distConditions, 'ShadowAttribute.deleted' => 0))
		));
		if (empty($sa)) throw new NotFoundException('Invalid proposal.');
		if (!$this->_isSiteAdmin()) {
			if ($sa['ShadowAttribute']['old_id'] != 0 && $sa['Event']['org_id'] != $this->Auth->user('org_id') && $sa['Event']['orgc_id'] != $this->Auth->user('org_id')) {
				$a = $this->ShadowAttribute->Event->Attribute->find('first', array(
					'recursive' => -1,
					'fields' => array('Attribute.id', 'Attribute.distribution'),
					'conditions' => array('Attribute.id' => $sa['ShadowAttribute']['old_id'], 'Attribute.distribution >' => 0)
				));
				if (empty($a)) throw new NotFoundException('Invalid proposal.');
			}
		}
		$this->set('ShadowAttribute', $sa['ShadowAttribute']);
		$this->set('_serialize', array('ShadowAttribute'));
	}

	public function index($eventId = false) {
		if (isset($this->request['named']['all'])) {
			$all = $this->request['named']['all'];
		} else {
			$all = false;
		}
		$conditions = array();
		if (!$this->_isSiteAdmin()) {
			if (!$all) {
				$conditions = array('Event.orgc_id' => $this->Auth->user('org_id'));
			} else {
				$conditions['AND'][] = array('ShadowAttribute.event_id' => $this->ShadowAttribute->Event->fetchEventIds($this->Auth->user(), false, false, false, true));
			}
		}
		if ($eventId && is_numeric($eventId)) $conditions['ShadowAttribute.event_id'] = $eventId;
		$conditions['deleted'] = 0;
		$this->set('all', $all);
		if ($this->_isRest()) {
			$temp = $this->ShadowAttribute->find('all', array(
					'conditions' => $conditions,
					'fields' => array('ShadowAttribute.id', 'ShadowAttribute.old_id', 'ShadowAttribute.event_id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.uuid', 'ShadowAttribute.to_ids', 'ShadowAttribute.value', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.timestamp', 'ShadowAttribute.proposal_to_delete'),
					'contain' => array(
							'Event' => array(
									'fields' => array('id', 'org_id', 'info', 'orgc_id'),
									'Orgc' => array('fields' => array('Orgc.name'))
							),
							'Org' => array(
								'fields' => array('name'),
							)
					),
					'recursive' => 1
			));
			if (empty($temp)) throw new MethodNotAllowedException('No proposals found or invalid event.');
			$proposals = array();
			foreach ($temp as $proposal) {
				$proposal['ShadowAttribute']['org'] = $proposal['Org']['name'];
				$proposals[] = $proposal['ShadowAttribute'];
			}
			$this->set('ShadowAttribute', $proposals);
			$this->set('_serialize', array('ShadowAttribute'));
		} else {
			$this->paginate = array(
					'conditions' => $conditions,
					'fields' => array('ShadowAttribute.id', 'ShadowAttribute.old_id', 'ShadowAttribute.event_id', 'ShadowAttribute.type', 'ShadowAttribute.category', 'ShadowAttribute.uuid', 'ShadowAttribute.to_ids', 'ShadowAttribute.value', 'ShadowAttribute.comment', 'ShadowAttribute.org_id', 'ShadowAttribute.timestamp'),
					'contain' => array(
							'Event' => array(
									'fields' => array('id', 'org_id', 'info', 'orgc_id'),
									'Orgc' => array('fields' => array('Orgc.name'))
							),
							'Org' => array(
								'fields' => array('name'),
							)
					),
					'recursive' => 1
			);
			$this->set('shadowAttributes', $this->paginate());
		}
	}

	// takes a uuid and finds all proposals that belong to an event with the given uuid. These are then returned.
	public function getProposalsByUuid($uuid) {
		if (!$this->_isRest() || !$this->userRole['perm_sync']) {
			throw new MethodNotAllowedException(__('This feature is only available using the API to Sync users'));
		}
		if (strlen($uuid) != 36) {
			throw new NotFoundException(__('Invalid UUID'));
		}
		$temp = $this->ShadowAttribute->find('all', array(
				'conditions' => array('event_uuid' => $uuid),
				'recursive' => -1,
				'contain' => array(
					'Org' => array('fields' => array('uuid', 'name')),
					'EventOrg' => array('fields' => array('uuid', 'name')),
				)
		));
		foreach ($temp as $key => $t) {
			if ($this->ShadowAttribute->typeIsAttachment($t['ShadowAttribute']['type'])) {
				$temp[$key]['ShadowAttribute']['data'] = $this->ShadowAttribute->base64EncodeAttachment($t['ShadowAttribute']);
			}
		}
		if ($temp == null) {
			$this->response->statusCode(404);
			$this->set('name', 'No proposals found.');
			$this->set('message', 'No proposals found');
			$this->set('errors', 'No proposals found');
			$this->set('url', '/shadow_attributes/getProposalsByUuid/' . $uuid);
			$this->set('_serialize', array('name', 'message', 'url', 'errors'));
			$this->response->send();
			return false;
		} else {
			$this->set('proposal', $temp);
			$this->render('get_proposals_by_uuid');
		}
	}

	public function getProposalsByUuidList() {
		if (!$this->_isRest() || !$this->userRole['perm_sync']) {
			throw new MethodNotAllowedException(__('This feature is only available using the API to Sync users'));
		}
		if (!$this->request->is('Post')) throw new MethodNotAllowedException('This feature is only available using POST requests');
		$result = array();
		if (!empty($this->request->data)) {
			foreach ($this->request->data as $eventUuid) {
				$temp = $this->ShadowAttribute->find('all', array(
						'conditions' => array('event_uuid' => $eventUuid),
						'recursive' => -1,
						'contain' => array(
								'Org' => array('fields' => array('uuid', 'name')),
								'EventOrg' => array('fields' => array('uuid', 'name')),
						),
				));
				if (empty($temp)) continue;
				foreach ($temp as $key => $t) {
					if ($this->ShadowAttribute->typeIsAttachment($t['ShadowAttribute']['type'])) {
						$temp[$key]['ShadowAttribute']['data'] = $this->ShadowAttribute->base64EncodeAttachment($t['ShadowAttribute']);
					}
				}
				$result = array_merge($result, $temp);
			}
		}
		if (empty($result)) {
			$this->response->statusCode(404);
			$this->set('name', 'No proposals found.');
			$this->set('message', 'No proposals found');
			$this->set('errors', 'No proposals found');
			$this->set('url', '/shadow_attributes/getProposalsByUuidList');
			$this->set('_serialize', array('name', 'message', 'url', 'errors'));
			$this->response->send();
			return false;
		} else {
			$this->set('result', $result);
			$this->render('get_proposals_by_uuid_list');
		}
	}

	public function fetchEditForm($id, $field = null) {
		$validFields = array('value', 'comment', 'type', 'category', 'to_ids');
		if (!isset($field) || !in_array($field, $validFields)) throw new MethodNotAllowedException('Invalid field requested.');
		$this->loadModel('Attribute');
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}

		$fields = array('id', 'distribution', 'event_id');
		if ($field == 'category' || $field == 'type') {
			$fields[] = 'type';
			$fields[] = 'category';
		} else {
			$fields[] = $field;
		}
		$attribute = $this->Attribute->find('first', array(
				'recursive' => -1,
				'conditions' => array('Attribute.id' => $id),
				'fields' => $fields,
				'contain' => array(
						'Event' => array(
								'fields' => array('distribution', 'id', 'user_id', 'orgc_id', 'org_id'),
						)
				)
		));
		if (!$this->_isSiteAdmin()) {
			if ($attribute['Event']['orgc_id'] != $this->Auth->user('org_id') && ($attribute['Event']['org_id'] == $this->Auth->user('org_id') || $attribute['Event']['distribution'] > 0)) {
				// Allow the edit
			} else {
				throw new NotFoundException(__('Invalid attribute'));
			}
		}
		$this->layout = 'ajax';
		if ($field == 'distribution') $this->set('distributionLevels', $this->Attribute->distributionLevels);
		if ($field == 'category') {
			$typeCategory = array();
			foreach ($this->Attribute->categoryDefinitions as $k => $category) {
				foreach ($category['types'] as $type) {
					$typeCategory[$type][] = $k;
				}
			}
			$this->set('typeCategory', $typeCategory);
		}
		if ($field == 'type') {
			$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
		}
		$this->set('object', $attribute['Attribute']);
		$fieldURL = ucfirst($field);
		$this->render('ajax/attributeEdit' . $fieldURL . 'Form');
	}

	// ajax edit - post a single edited field and this method will attempt to create a proposal and return a json with the validation errors if they occur.
	public function editField($id) {
		if ((!$this->request->is('post') && !$this->request->is('put')) || !$this->request->is('ajax')) throw new MethodNotAllowedException();
		$this->loadModel('Attribute');
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$this->Attribute->recursive = -1;
		$this->Attribute->contain('Event');
		$attribute = $this->Attribute->read();

		if (!$this->_isSiteAdmin()) {
			if ($attribute['Event']['orgc_id'] != $this->Auth->user('org_id') && ($attribute['Event']['org_id'] == $this->Auth->user('org_id') || $attribute['Event']['distribution'] > 0)) {
				// Allow the edit
			} else {
				throw new NotFoundException(__('Invalid attribute'));
			}
		}

		$keys = array_flip(array('uuid', 'event_id', 'value', 'type', 'category', 'to_ids'));

		$proposal = array_intersect_key($attribute['Attribute'], $keys);
		$proposal['email'] = $this->Auth->user('email');
		$proposal['org_id'] = $this->Auth->user('org_id');
		$proposal['event_uuid'] = $attribute['Event']['uuid'];
		$proposal['event_org_id'] = $attribute['Event']['orgc_id'];
		$proposal['old_id'] = $attribute['Attribute']['id'];
		foreach ($this->request->data['ShadowAttribute'] as $changedKey => $changedField) {
			if ($proposal[$changedKey] == $changedField) {
				$this->autoRender = false;
				return new CakeResponse(array('body'=> json_encode('nochange'), 'status'=>200, 'type' => 'json'));
			}
			$proposal[$changedKey] = $changedField;
		}

		if ($this->ShadowAttribute->save($proposal)) {
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status'=>200, 'type' => 'json'));
		} else {
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode(array('fail' => false, 'errors' => $this->ShadowAttribute->validationErrors)), 'status'=>200, 'type' => 'json'));
		}
	}

	public function discardSelected($id) {
		if (!$this->request->is('post') || !$this->request->is('ajax')) throw new MethodNotAllowedException();

		// get a json object with a list of proposal IDs to be discarded
		// check each of them and return a json object with the successful discards and the failed ones.
		$ids = json_decode($this->request->data['ShadowAttribute']['ids_discard']);
		if (!$this->_isSiteAdmin()) {
			$event = $this->ShadowAttribute->Event->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'orgc_id', 'user_id')
			));
			if ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || (!$this->userRole['perm_modify_org'] && !($this->userRole['perm_modify'] && $event['Event']['user_id'] == $this->Auth->user('id')))) {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
			}
		}

		// find all attributes from the ID list that also match the provided event ID.
		$shadowAttributes = $this->ShadowAttribute->find('all', array(
				'recursive' => -1,
				'conditions' => array('id' => $ids, 'event_id' => $id),
				'fields' => array('id', 'event_id')
		));
		$successes = array();
		foreach ($shadowAttributes as $a) {
			if ($this->discard($a['ShadowAttribute']['id'])) $successes[] = $a['ShadowAttribute']['id'];
		}
		$fails = array_diff($ids, $successes);
		$this->autoRender = false;
		if (count($fails) == 0 && count($successes) > 0) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' deleted.')), 'status'=>200, 'type' => 'json'));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' deleted, but ' . count($fails) . ' proposal' . (count($fails) != 1 ? 's' : '') . ' could not be deleted.')), 'status'=>200, 'type' => 'json'));
		}
	}

	public function acceptSelected($id) {
		if (!$this->request->is('post') || !$this->request->is('ajax')) throw new MethodNotAllowedException();

		// get a json object with a list of proposal IDs to be accepted
		// check each of them and return a json object with the successful accepts and the failed ones.
		$ids = json_decode($this->request->data['ShadowAttribute']['ids_accept']);
		if (!$this->_isSiteAdmin()) {
			$event = $this->ShadowAttribute->Event->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'orgc_id', 'user_id')
			));
			if ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || (!$this->userRole['perm_modify_org'] && !($this->userRole['perm_modify'] && $event['Event']['user_id'] == $this->Auth->user('id')))) {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
			}
		}

		// find all attributes from the ID list that also match the provided event ID.
		$shadowAttributes = $this->ShadowAttribute->find('all', array(
				'recursive' => -1,
				'conditions' => array('id' => $ids, 'event_id' => $id),
				'fields' => array('id', 'event_id')
		));
		$successes = array();
		foreach ($shadowAttributes as $a) {
			$response = $this->__accept($a['ShadowAttribute']['id']);
			if (isset($response['saved'])) $successes[] = $a['ShadowAttribute']['id'];
		}
		$fails = array_diff($ids, $successes);
		$this->autoRender = false;
		if (count($fails) == 0 && count($successes) > 0) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' accepted.')), 'status'=>200, 'type' => 'json'));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' accepted, but ' . count($fails) . ' proposal' . (count($fails) != 1 ? 's' : '') . ' could not be accepted.')), 'status'=>200, 'type' => 'json'));
		}
	}

	public function generateCorrelation() {
		if (!self::_isSiteAdmin() || !$this->request->is('post')) throw new NotFoundException();
		if (!Configure::read('MISP.background_jobs')) {
			$k = $this->ShadowAttribute->generateCorrelation();
			$this->Session->setFlash(__('All done. ' . $k . ' proposals processed.'));
			$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
		} else {
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'generate proposal correlation',
					'job_input' => 'All attributes',
					'status' => 0,
					'retries' => 0,
					'org' => 'ADMIN',
					'message' => 'Job created.',
			);
			$job->save($data);
			$jobId = $job->id;
			$process_id = CakeResque::enqueue(
					'default',
					'AdminShell',
					array('jobGenerateShadowAttributeCorrelation', $jobId)
			);
			$job->saveField('process_id', $process_id);
			$this->Session->setFlash(__('Job queued. You can view the progress if you navigate to the active jobs view (administration -> jobs).'));
			$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
		}
	}
}
