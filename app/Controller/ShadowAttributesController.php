<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

/**
 * ShadowAttributes Controller
 *
 * Handles requests to edit attributes, add attributes
 *
 * @property ShadowAttribute $ShadowAttribute
 */
class ShadowAttributesController extends AppController {

	public $components = array('Acl', 'Security', 'RequestHandler', 'Email');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,
		);

	public $helpers = array('Js' => array('Jquery'));

	public function beforeFilter() {
		parent::beforeFilter();

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
		$this->ShadowAttribute->id = $id;
		$this->ShadowAttribute->recursive = -1;
		$this->ShadowAttribute->read();
		$shadow = $this->ShadowAttribute->data['ShadowAttribute'];
		// If the old_id is set to anything but 0 then we're dealing with a proposed edit to an existing attribute
		if ($shadow['old_id'] != 0) {
			// Find the live attribute by the shadow attribute's uuid, so we can begin editing it
			$this->Attribute->contain = 'Event';
			$activeAttribute = $this->Attribute->findByUuid($this->ShadowAttribute->data['ShadowAttribute']['uuid']);
				
			// Send those away that shouldn't be able to see this
			if (!$this->_isSiteAdmin()) {
				if ($activeAttribute['Event']['orgc_id'] != $this->Auth->user('org_id') || (!$this->userRole['perm_modify'])) {
					$this->Session->setFlash('You don\'t have permission to do that');
					$this->redirect(array('controller' => 'events', 'action' => 'view', $this->ShadowAttribute->data['ShadowAttribute']['event_id']));
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
			$fieldList = array('proposal_email_lock', 'id', 'info', 'published', 'timestamp');
			$event['Event']['timestamp'] = $date->getTimestamp();
			$event['Event']['proposal_email_lock'] = 0;
			$event['Event']['published'] = 0;
			if ($this->Event->save($event, array('fieldList' => $fieldList))) {
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
				return array('false' => true, 'errors' => 'Could not accept proposal.');
			}
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
			$attribute['distribution'] = $event['Event']['distribution'];
			$this->Attribute->create();
			$this->Attribute->save($attribute);
			if ($this->ShadowAttribute->typeIsAttachment($shadow['type'])) {
				$this->_moveFile($toDeleteId, $this->Attribute->id, $shadow['event_id']);
			}
			$this->ShadowAttribute->setDeleted($toDeleteId);
		
			$fieldList = array('proposal_email_lock', 'id', 'info', 'published');
			if ($this->Auth->user('org_id') == $event['Event']['orgc_id']) {
				$event['Event']['proposal_email_lock'] = 0;
			}
			$event['Event']['published'] = 0;
			$date = new DateTime();
			$event['Event']['timestamp'] = $date->getTimestamp();
			$this->autoRender = false;
			if ($this->Event->save($event, array('fieldList' => $fieldList))) {
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
			} else {
				return array('false' => true, 'errors' => 'Could not accept proposal.');
			}
		}
	}
	
/**
 * accept method
 *
 * @return void
 *
 */
	// Accept a proposed edit and update the attribute
	public function accept($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		if ($this->_isRest()) {
			throw new Exception('This feature is limited to interactive users only.');
		}
		$response = $this->__accept($id);
		return new CakeResponse(array('body'=> json_encode($response),'status'=>200));
	}

	// If we accept a proposed attachment, then the attachment itself needs to be moved from files/eventId/shadow/shadowId to files/eventId/attributeId
	private function _moveFile($shadowId, $newId, $eventId){
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
			$this->ShadowAttribute->id = $id;
			$sa = $this->ShadowAttribute->read();
			$eventId = $this->ShadowAttribute->data['ShadowAttribute']['event_id'];
			$this->loadModel('Event');
			$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
			$this->Event->recursive = -1;
			$this->Event->id = $eventId;
			$this->Event->read();
			// Send those away that shouldn't be able to see this
			if (!$this->_isSiteAdmin()) {
				if ((($this->Event->data['Event']['orgc_id'] != $this->Auth->user('org_id')) && ($this->Auth->user('org_id') != $this->ShadowAttribute->data['ShadowAttribute']['org_id'])) || (!$this->userRole['perm_modify'])) {
					return false;
				}
			}
			if ($this->ShadowAttribute->setDeleted($id)) {
				if ($this->Auth->user('org_id') == $this->Event->data['Event']['orgc_id']) {
					$this->_setProposalLock($eventId, false);
				}
				$this->autoRender = false;
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
	
/**
 * discard method
 *
 * @return void
 *
 */
	// This method will discard a proposed change. Users that can delete the proposals are the publishing users of the org that created the event and of the ones that created the proposal - in addition to site admins of course
	public function discard($id = null) {
		if (!$this->request->is('ajax')) {
			throw new MethodNotAllowedException();
		}
		if ($this->request->is('post')) {
			if ($this->__discard($id)) {
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Proposal discarded.')),'status'=>200));
			} else {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Could not discard proposal.')),'status'=>200));
			}
		} else {
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

/**
 * add method
 *
 * @return void
 *
 * @throws NotFoundException // TODO Exception
 */
	public function add($eventId = null) {
		if ($this->request->is('ajax'))	{
			$this->set('ajax', true);
			//$this->autoRender = false;
			$this->layout = 'ajax';
		}
		else $this->set('ajax', false);
		$event = $this->ShadowAttribute->Event->find('first', array(
				'conditions' => array('Event.id' => $eventId),
				'recursive' => -1,
				'fields' => array('id', 'orgc_id', 'distribution', 'org_id'),
		));
		if (!$this->_isSiteAdmin() && (($event['Event']['distribution'] == 0 && $event['Event']['org_id'] != $this->Auth->user('org_id'))) || ($event['Event']['orgc_id'] == $this->Auth->user('org_id'))) {
			$this->Session->setFlash(__('Invalid Event.'));
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		}
		if ($this->request->is('post')) {
			if ($this->request->is('ajax')) $this->autoRender = false;
			// Give error if someone tried to submit a attribute with attachment or malware-sample type.
			// TODO change behavior attachment options - this is bad ... it should rather by a messagebox or should be filtered out on the view level
			if (isset($this->request->data['ShadowAttribute']['type']) && $this->ShadowAttribute->typeIsAttachment($this->request->data['ShadowAttribute']['type'])) {
				$this->Session->setFlash(__('Attribute has not been added: attachments are added by "Add attachment" button', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
			}
			$temp = $this->_getEventData($this->request->data['ShadowAttribute']['event_id']);
			$event_uuid = $temp['uuid'];
			$event_org = $temp['orgc_id'];
			//
			// multiple attributes in batch import
			//
			
			if ((isset($this->request->data['ShadowAttribute']['batch_import']) && $this->request->data['ShadowAttribute']['batch_import'] == 1)) {
				// make array from value field
				$attributes = explode("\n", $this->request->data['ShadowAttribute']['value']);
				$fails = "";	// will be used to keep a list of the lines that failed or succeeded
				$successes = "";
				// TODO loop-holes,
				// the value null value thing
				foreach ($attributes as $key => $attribute) {
					$attribute = trim($attribute);
					if (strlen($attribute) == 0)
					continue; // don't do anything for empty lines
					$this->ShadowAttribute->create();
					$this->request->data['ShadowAttribute']['value'] = $attribute; // set the value as the content of the single line
					$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
					$this->request->data['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
					$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
					$this->request->data['ShadowAttribute']['event_org_id'] = $event_org;
					// TODO loop-holes,
					// there seems to be a loop-hole in misp here
					// be it an create and not an update
					$this->ShadowAttribute->id = null;
					if ($this->ShadowAttribute->save($this->request->data)) {
						$successes .= " " . ($key + 1);
					} else {
						$fails .= " " . ($key + 1);
					}
				}
				// we added all the attributes,
				if ($this->request->is('ajax')) {
					$this->autoRender = false;
					// handle it if some of them failed!!!!
					if ($fails) {
						$error_message = 'The lines' . $fails . ' could not be saved. Please, try again.';
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $error_message)), 'status' => 200));
					} else {
						return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200));
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
						if (!$this->__sendProposalAlertEmail($eventId) == false) $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
						$this->Session->setFlash(__('The lines' . $successes . ' have been saved' . $emailResult, true));
					}
				}

				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));

			} else {
				if (isset($this->request->data['ShadowAttribute']['uuid'])) {	// TODO here we should start RESTful dialog
					// check if the uuid already exists
				}

				//
				// single attribute
				//
				// create the attribute
				$this->ShadowAttribute->create();
				$savedId = $this->ShadowAttribute->getId();
				$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
				$this->request->data['ShadowAttribute']['org_id'] = $this->Auth->user('org_id');
				$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
				$this->request->data['ShadowAttribute']['event_org_id'] = $event_org;
				if ($this->ShadowAttribute->save($this->request->data)) {
					// list the ones that succeeded
					$emailResult = "";
					if (!$this->__sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id'])) {
						$emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
					}
					// inform the user and redirect
					if ($this->request->is('ajax')) {
						$this->autoRender = false;
						return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Proposal added' . $emailResult)),'status'=>200));
					} else {
						$this->Session->setFlash(__('The proposal has been saved'));
						$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
					}
				} else {
					if ($this->request->is('ajax')) {
						$this->autoRender = false;
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $this->Attribute->validationErrors)),'status'=>200));
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
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobos for categories
		$categories = array_keys($this->ShadowAttribute->Event->Attribute->categoryDefinitions);
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', compact('categories'));
		// combobox for distribution
		$count = 0;

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
			'contain' => array('Event' => array('fields' => array('Event.org', 'Event.distribution', 'Event.id'))),
			'conditions' => array('ShadowAttribute.id' => $id)
		));
		if (!$this->_isSiteAdmin() &&
			$this->Auth->user('org') !=
			$sa['Event']['org'] &&
			$sa['Event']['distribution'] == 0) {
			throw new UnauthorizedException('You do not have the permission to view this event.');
		}
		$this->__downloadAttachment($sa['ShadowAttribute']);
	}
	
	private function __downloadAttachment($shadowAttribute) {
		$path = "files" . DS . $shadowAttribute['event_id'] . DS . 'shadow' . DS;
		$file = $shadowAttribute['id'];
		$filename = '';
		if ('attachment' == $shadowAttribute['type']) {
			$filename = $shadowAttribute['value'];
			$fileExt = pathinfo($filename, PATHINFO_EXTENSION);
			$filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
		} elseif ('malware-sample' == $shadowAttribute['type']) {
			$filenameHash = explode('|', $shadowAttribute['value']);
			$filename = $filenameHash[0];
			$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
			$fileExt = "zip";
		} else {
			throw new NotFoundException(__('Proposal not an attachment or malware-sample'));
		}
		$this->autoRender = false;
		$this->response->type($fileExt);
		$this->response->file($path . $file, array('download' => true, 'name' => $filename . '.' . $fileExt));
	}

/**
 * add_attachment method
 *
 * @return void
 * @throws InternalErrorException
 */
	public function add_attachment($eventId = null) {
		$event = $this->ShadowAttribute->Event->find('first', array(
				'conditions' => array('Event.id' => $eventId),
				'recursive' => -1,
				'fields' => array('id', 'orgc_id', 'distribution', 'org_id'),
		));
		if ((($event['Event']['distribution'] == 0 && $event['Event']['org_id'] != $this->Auth->user('org_id'))) || ($event['Event']['orgc_id'] == $this->Auth->user('org_id'))) {
			$this->Session->setFlash(__('Invalid Event.'));
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		}
		if ($this->request->is('post')) {
			$temp = $this->_getEventData($this->request->data['ShadowAttribute']['event_id']);
			// Check if there were problems with the file upload
			// only keep the last part of the filename, this should prevent directory attacks
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
			
			$filename = basename($this->request->data['ShadowAttribute']['value']['name']);
			$tmpfile = new File($this->request->data['ShadowAttribute']['value']['tmp_name']);
			$hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
			$event_uuid = $temp['uuid'];
			$event_org = $temp['orgc_id'];
			// save the file-info in the database
			$this->ShadowAttribute->create();
			if ($this->request->data['ShadowAttribute']['malware']) {
				$result = $this->Event->Attribute->handleMaliciousBase64($this->request->data['ShadowAttribute']['event_id'], $filename, base64_encode($tmpfile->read()), array_keys($hashes));
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
									'to_ids' => 1,
									'email' => $this->Auth->user('email'),
									'org_id' => $this->Auth->user('org_id'),
									'event_uuid' => $event_uuid,
									'event_org_id' => $event_org,
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
								'data' => base64_encode($tmpfile->read()),
								'to_ids' => 0,
								'email' => $this->Auth->user('email'),
								'org_id' => $this->Auth->user('org_id'),
								'event_uuid' => $event_uuid,
								'event_org_id' => $event_org,
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
				if (!$this->__sendProposalAlertEmail($eventId)) $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
				if (empty($fails)) $this->Session->setFlash(__('The attachment has been uploaded'));
				else $this->Session->setFlash(__('The attachment has been uploaded, but some of the proposals could not be created. The failed proposals are: ' . implode(', ', $fails)));
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
						continue;
					}
				}
			}
		};
		$categories = $this->_arrayToValuesIndexArray($selectedCategories);
		$this->set('categories',$categories);

		$this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);

		$this->set('zippedDefinitions', $this->ShadowAttribute->zippedDefinitions);
		$this->set('uploadDefinitions', $this->ShadowAttribute->uploadDefinitions);

	}

/**
 * edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	// Propose an edit to an attribute
	public function edit($id = null) {
		if ($this->request->is('ajax'))	{
			$this->set('ajax', true);
			$this->layout = 'ajax';
		}
		$this->loadModel('Attribute');
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid Attribute'));
		}
		$this->Attribute->read();
		if ($this->_isRest()) {
			throw new Exception ('Proposing a change to an attribute can only be done via the interactive interface.');
		}
		$uuid = $this->Attribute->data['Attribute']['uuid'];
		if (!$this->_isSiteAdmin()) {
			// If the attribute's distribution is private and the user is not the owner of the event or if the user is of the original creator org -> exception
			// The owner should be able to create a shadow attribute, since a pushed community event would be private and tied to a single organisation on a synced instance
			// The users of that organisation can only view but not edit the event, but they should be able to propose a change 
			if ((($this->Attribute->data['Attribute']['distribution'] == 0 && $this->Attribute->data['Event']['org_id'] != $this->Auth->user('org_id'))) || ($this->Attribute->data['Event']['orgc_id'] == $this->Auth->user('org_id'))) {
				$this->Session->setFlash(__('Invalid Attribute.'));
				$this->redirect(array('controller' => 'events', 'action' => 'index'));
			}
		}

		// Check if the attribute is an attachment, if yes, block the type and the value fields from being edited.
		$eventId = $this->Attribute->data['Attribute']['event_id'];
		if ('attachment' == $this->Attribute->data['Attribute']['type'] || 'malware-sample' == $this->Attribute->data['Attribute']['type'] ) {
			$this->set('attachment', true);
			$attachment = true;
		} else {
			$this->set('attachment', false);
			$attachment = false;
		}

		if ($this->request->is('post') || $this->request->is('put')) {
			$existingAttribute = $this->Attribute->findByUuid($uuid);
			$temp = $this->_getEventData($eventId);
			$event_uuid = $temp['uuid'];
			$event_org = $temp['orgc_id'];
			$this->request->data['ShadowAttribute']['old_id'] = $existingAttribute['Attribute']['id'];
			$this->request->data['ShadowAttribute']['uuid'] = $existingAttribute['Attribute']['uuid'];
			$this->request->data['ShadowAttribute']['event_id'] = $existingAttribute['Attribute']['event_id'];
			$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
			$this->request->data['ShadowAttribute']['event_org_id'] = $event_org;
			if ($attachment) $this->request->data['ShadowAttribute']['value'] = $existingAttribute['Attribute']['value'];
			if ($attachment) $this->request->data['ShadowAttribute']['type'] = $existingAttribute['Attribute']['type'];
			$this->request->data['ShadowAttribute']['org_id'] =  $this->Auth->user('org_id');
			$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
			$this->request->data['ShadowAttribute']['proposal_to_delete'] = false;
			if ($this->ShadowAttribute->save($this->request->data)) {
				$emailResult = "";
				if (!$this->__sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id'])) $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
				$this->Session->setFlash(__('The proposed Attribute has been saved' . $emailResult));
				$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
			} else {
				$this->Session->setFlash(__('The ShadowAttribute could not be saved. Please, try again.'));
			}
		} else {
			// Read the attribute that we're about to edit
			$this->ShadowAttribute->create();
			$this->Attribute->recursive = -1;
			$request = $this->Attribute->read(null, $id);
			$request['ShadowAttribute'] = $request['Attribute'];
			$this->request->data = $request;
			unset($this->request->data['ShadowAttribute']['id']);
		}

		// combobox for types
		$types = array_keys($this->ShadowAttribute->typeDefinitions);
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobox for categories
		$categories = $this->_arrayToValuesIndexArray(array_keys($this->ShadowAttribute->Event->Attribute->categoryDefinitions));
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', $categories);

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
			if (empty($existingAttribute)) return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Invalid Attribute.')),'status'=>200));
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
				if (!$this->__sendProposalAlertEmail($existingAttribute['Event']['id'])) $emailResult = " but sending out the alert e-mails has failed for at least one recipient.";
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'The proposal to delete the attribute has been saved' . $emailResult)),'status'=>200));
			} else {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'Could not create proposal.')),'status'=>200));
			}
		} else {
			if (empty($existingAttribute)) throw new NotFoundException(__('Invalid Attribute'));
			$this->set('id', $id);
			$this->set('event_id', $existingAttribute['Attribute']['event_id']);
			$this->render('ajax/deletionProposalConfirmationForm');
		}
	}
	
	private function _setProposalLock($id, $lock = true) {
		$this->loadModel('Event');
		$this->Event->recursive = -1;
		$event = $this->Event->read(null, $id);
		if ($lock) {
			$event['Event']['proposal_email_lock'] = 1;
		} else {
			$event['Event']['proposal_email_lock'] = 0;
		}
		$fieldList = array('proposal_email_lock', 'id', 'info');
		$this->Event->save($event, array('fieldList' => $fieldList));
	}
	
	
	private function __sendProposalAlertEmail($id) {
		$this->loadModel('Event');
		$this->Event->recursive = -1;
		$event = $this->Event->read(null, $id);
		
		// If the event has an e-mail lock, return
		if ($event['Event']['proposal_email_lock'] == 1) {
			return;
		} else {
			$this->_setProposalLock($id);
		}
		try {
			$this->loadModel('User');
			$this->User->recursive = -1;
			$orgMembers = array();
			$temp = $this->User->findAllByOrg($event['Event']['orgc_id'], array('email', 'gpgkey', 'contactalert', 'id'));
			foreach ($temp as $tempElement) {
				if ($tempElement['User']['contactalert'] || $tempElement['User']['id'] == $event['Event']['user_id']) {
					array_push($orgMembers, $tempElement);
				}
			}
			$body = "";
			$body .= "Hello, \n";
			$body .= "\n";
			$body .= "A user of another organisation has proposed a change to an event created by you or your organisation. \n";
			$body .= "\n";
			$body .= "To view the event in question, follow this link:";
			$body .= ' ' . Configure::read('MISP.baseurl') . '/events/view/' . $id . "\n";
			$body .= "\n";
			$body .= "You can reach the user at " . $this->Auth->user('email');
			$body .= "\n";
	
			// sign the body
			require_once 'Crypt/GPG.php';
			$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg')));
			$gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
			$bodySigned = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
			// Add the GPG key of the user as attachment
			// LATER sign the attached GPG key
			if (null != (!$this->User->getPGP($this->Auth->user('id')))) {
				// save the gpg key to a temporary file
				$tmpfname = tempnam(TMP, "GPGkey");
				$handle = fopen($tmpfname, "w");
				fwrite($handle, $this->User->getPGP($this->Auth->user('id')));
				fclose($handle);
				// attach it
				$this->Email->attachments = array(
						'gpgkey.asc' => $tmpfname
				);
			}
	
			foreach ($orgMembers as &$reporter) {
				if (!empty($reporter['User']['gpgkey'])) {
					// import the key of the user into the keyring
					// this isn't really necessary, but it gives it the fingerprint necessary for the next step
					$keyImportOutput = $gpg->importKey($reporter['User']['gpgkey']);
					// say what key should be used to encrypt
					try {
						$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir'), 'binary' => (Configure::read('GnuPG.binary') ? Configure::read('GnuPG.binary') : '/usr/bin/gpg')));
						$gpg->addEncryptKey($keyImportOutput['fingerprint']); // use the key that was given in the import
						$bodyEncSig = $gpg->encrypt($bodySigned, true);
					} catch (Exception $e){
						// catch errors like expired PGP keys
						$this->log($e->getMessage());
						// no need to return here, as we want to send out mails to the other users if GPG encryption fails for a single user
					}
				} else {
					$bodyEncSig = $bodySigned;
					// FIXME should I allow sending unencrypted "contact" mails to people if they didn't import they GPG key?
				}
				// prepare the email
				$this->Email->from = Configure::read('MISP.email');
				$this->Email->to = $reporter['User']['email'];
				$this->Email->subject = "[" . Configure::read('MISP.org') . " MISP] Proposal to event #" . $id;
				$this->Email->template = 'body';
				$this->Email->sendAs = 'text';		// both text or html
				$this->set('body', $bodyEncSig);
				// Add the GPG key of the user as attachment
				// LATER sign the attached GPG key
				if (null != ($this->User->getPGP($this->Auth->user('id')))) {
					// attach the gpg key
					$this->Email->attachments = array(
						'gpgkey.asc' => $tmpfname
					);
				}
				// send it
				$result = $this->Email->send();
				// If you wish to send multiple emails using a loop, you'll need
				// to reset the email fields using the reset method of the Email component.
				$this->Email->reset();
			}
		} catch (Exception $e) {
			return false;
		}
		return true;
	}
	
	public function index() {
		$conditions = null;
		if (!$this->_isSiteAdmin()) {
			$conditions = array('Event.org =' => $this->Auth->user('org_id'));
		}
		$conditions[] = array('deleted' => 0);
		$this->paginate = array(
				'conditions' => $conditions,
				'fields' => array('id', 'org_id', 'old_id', 'deleted', 'value', 'category', 'type'),
				'contain' => array(
						'Event' => array(
								'fields' => array('id', 'org_id', 'info', 'orgc_id'),
						),
						'Org' => array(
								'fields' => array('name'),
						)
				),
				'recursive' => 1	
		);
		$this->set('shadowAttributes', $this->paginate());
	}
	
	private function _getEventData($event_id) {
		$this->loadModel('Event');
		$this->Event->recursive = -1;
		$this->Event->read(array('id', 'uuid', 'orgc_id'), $event_id);
		return $this->Event->data['Event'];
	} 
	
	// takes a uuid and finds all proposals that belong to an event with the given uuid. These are then returned. 
	public function getProposalsByUuid($uuid) {
		if (!$this->_isRest() || !$this->userRole['perm_sync']) {
			throw new MethodNotAllowedException(__('This feature is only available using the API to Sync users'));
		}
		if (strlen($uuid) != 36) {
			throw new NotFoundException(__('Invalid UUID'));
		}
		$this->ShadowAttribute->recursive = -1;
		$temp = $this->ShadowAttribute->findAllByEventUuid($uuid);
		if ($temp == null) throw new NotFoundException(__('Invalid event'));
		$this->set('proposal', $temp);
		$this->render('get_proposals_by_uuid');
	}
	
	public function fetchEditForm($id, $field = null) {
		$validFields = array('value', 'comment', 'type', 'category', 'to_ids');
		if (!isset($field) || !in_array($field, $validFields)) throw new MethodNotAllowedException('Invalid field requested.');
		//if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This function can only be accessed via AJAX.');
		$this->loadModel('Attribute');
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
	
		$fields = array('id', 'distribution', 'event_id');
		$additionalFieldsToLoad = $field;
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
			//
			if ($attribute['Event']['orgc_id'] != $this->Auth->user('org_id')	&& ($attribute['Event']['org_id'] == $this->Auth->user('org_id') || $attribute['Event']['distribution'] > 0)) {
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
		$this->LoadModel('Attribute');
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$this->Attribute->recursive = -1;
		$this->Attribute->contain('Event');
		$attribute = $this->Attribute->read();
	
		if (!$this->_isSiteAdmin()) {
			//
			if ($attribute['Event']['orgc_id'] != $this->Auth->user('org_id')	&& ($attribute['Event']['org_id'] == $this->Auth->user('org_id') || $attribute['Event']['distribution'] > 0)) {
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
				return new CakeResponse(array('body'=> json_encode('nochange'),'status'=>200));
			}
			$proposal[$changedKey] = $changedField;
		}
		
		if ($this->ShadowAttribute->save($proposal)) {
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode(array('saved' => true)),'status'=>200));
		} else {
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode(array('fail' => false, 'errors' => $this->ShadowAttribute->validationErrors)),'status'=>200));
		}
	}
	
	public function discardSelected($id) {
		if (!$this->request->is('post') && !$this->request->is('ajax')) throw new MethodNotAllowedException();

		// get a json object with a list of proposal IDs to be discarded
		// check each of them and return a json object with the successful discards and the failed ones.
		$ids = json_decode($this->request->data['ShadowAttribute']['ids_discard']);
		if (!$this->_isSiteAdmin()) {
			$event = $this->ShadowAttribute->Event->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'orgc', 'user_id')
			));
			if ($event['Event']['orgc'] != $this->Auth->user('org') || (!$this->userRole['perm_modify_org'] && !($this->userRole['perm_modify'] && $event['Event']['user_id'] == $this->Auth->user('id')))) {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'You don\'t have permission to do that.')),'status'=>200));
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
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' deleted.')),'status'=>200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' deleted, but ' . count($fails) . ' proposal' . (count($fails) != 1 ? 's' : '') . ' could not be deleted.')),'status'=>200));
		}
	}
	
	public function acceptSelected($id) {
		if (!$this->request->is('post') && !$this->request->is('ajax')) throw new MethodNotAllowedException();
	
		// get a json object with a list of proposal IDs to be accepted
		// check each of them and return a json object with the successful accepts and the failed ones.
		$ids = json_decode($this->request->data['ShadowAttribute']['ids_accept']);
		if (!$this->_isSiteAdmin()) {
			$event = $this->ShadowAttribute->Event->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'orgc', 'user_id')
			));
			if ($event['Event']['orgc'] != $this->Auth->user('org') || (!$this->userRole['perm_modify_org'] && !($this->userRole['perm_modify'] && $event['Event']['user_id'] == $this->Auth->user('id')))) {
				return new CakeResponse(array('body'=> json_encode(array('false' => true, 'errors' => 'You don\'t have permission to do that.')),'status'=>200));
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
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' accepted.')),'status'=>200));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' proposal' . (count($successes) != 1 ? 's' : '') . ' accepted, but ' . count($fails) . ' proposal' . (count($fails) != 1 ? 's' : '') . ' could not be accepted.')),'status'=>200));
		}
	}
}
