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
								'Event.org =' => $this->Auth->user('org'),
								'AND' => array(
									'ShadowAttribute.org =' => $this->Auth->user('org'),
									'Event.distribution >' => 0,
								),
							)
			)));
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
				if ($activeAttribute['Event']['orgc'] != $this->Auth->user('org') || (!$this->userRole['perm_modify'])) {
					$this->Session->setFlash('You don\'t have permission to do that');
					$this->redirect(array('controller' => 'events', 'action' => 'view', $this->ShadowAttribute->data['ShadowAttribute']['event_id']));
				}
			}
			// Update the live attribute with the shadow data
			$activeAttribute['Attribute']['value1'] = $shadow['value1'];
			$activeAttribute['Attribute']['value2'] = $shadow['value2'];
			$activeAttribute['Attribute']['value'] = $shadow['value'];
			$activeAttribute['Attribute']['type'] = $shadow['type'];
			$activeAttribute['Attribute']['category'] = $shadow['category'];
			$activeAttribute['Attribute']['to_ids'] = $shadow['to_ids'];
			$this->Attribute->save($activeAttribute['Attribute']);
			$this->ShadowAttribute->delete($id, $cascade = false);
			$this->loadModel('Event');
			$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
			$this->Event->recursive = -1;
			// Unpublish the event, accepting a proposal is modifying the event after all. Also, reset the lock.
			$event = $this->Event->read(null, $activeAttribute['Attribute']['event_id']);
			$fieldList = array('proposal_email_lock', 'id', 'info', 'published', 'timestamp');
			$date = new DateTime();
			$event['Event']['timestamp'] = $date->getTimestamp();
			$event['Event']['proposal_email_lock'] = 0;
			$event['Event']['published'] = 0;
			$this->Event->save($event, array('fieldList' => $fieldList));
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => $this->Auth->user('org'),
					'model' => 'ShadowAttribute',
					'model_id' => $id,
					'email' => $this->Auth->user('email'),
					'action' => 'accept',
					'title' => 'Proposal (' . $shadow['id'] . ') of ' . $shadow['org'] . ' to Attribute (' . $shadow['old_id'] . ') of Event (' . $shadow['event_id'] . ') accepted - ' . $shadow['category'] . '/' . $shadow['type'] . ' ' . $shadow['value'],
					));
			$this->Session->setFlash(__('Proposed change accepted', true), 'default', array());
			$this->redirect(array('controller' => 'events', 'action' => 'view', $activeAttribute['Attribute']['event_id']));
			return;
		} else {
			// If the old_id is set to 0, then we're dealing with a brand new proposed attribute
			// The idea is to load the event that the new attribute will be attached to, create an attribute to it and set the distribution equal to that of the event
			$toDeleteId = $shadow['id'];
			$this->loadModel('Event');
			$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
			$this->Event->recursive = -1;
			$event = $this->Event->read(null, $shadow['event_id']);
			
			if (!$this->_isSiteAdmin()) {
				if (($event['Event']['orgc'] != $this->Auth->user('org')) || (!$this->userRole['perm_modify'])) {
					$this->Session->setFlash('You don\'t have permission to do that');
					$this->redirect(array('controller' => 'events', 'action' => 'index'));
				}
			}
			$shadowForLog = $shadow;
			// Stuff that we won't use in its current form for the attribute
			unset($shadow['email'], $shadow['org'], $shadow['id'], $shadow['old_id']);
			
			$attribute = $shadow;

			// set the distribution equal to that of the event
			$attribute['distribution'] = $event['Event']['distribution'];
			$this->Attribute->create();
			$this->Attribute->save($attribute);
			if ($this->ShadowAttribute->typeIsAttachment($shadow['type'])) {
				$this->_moveFile($toDeleteId, $this->Attribute->id, $shadow['event_id']);
			}
			$this->ShadowAttribute->delete($toDeleteId, $cascade = false);

			$fieldList = array('proposal_email_lock', 'id', 'info', 'published');
			$event['Event']['proposal_email_lock'] = 0;
			$event['Event']['published'] = 0;
			$this->Event->save($event, array('fieldList' => $fieldList));
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
					'org' => $this->Auth->user('org'),
					'model' => 'ShadowAttribute',
					'model_id' => $id,
					'email' => $this->Auth->user('email'),
					'action' => 'accept',
					'title' => 'Proposal (' . $shadowForLog['id'] . ') of ' . $shadowForLog['org'] . ' to Event(' . $shadowForLog['event_id'] . ') accepted',
					'change' => null,
					));
			$this->Session->setFlash(__('Proposed attribute accepted', true), 'default', array());
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->Event->id));
		}
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

/**
 * discard method
 *
 * @return void
 *
 */
	// This method will discard a proposed change. Users that can delete the proposals are the publishing users of the org that created the event and of the ones that created the proposal - in addition to site admins of course
	public function discard($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		if ($this->_isRest()) {
			throw new Exception('This feature is limited to interactive users only.');
		}
		$this->ShadowAttribute->id = $id;
		$this->ShadowAttribute->read();
		$eventId = $this->ShadowAttribute->data['ShadowAttribute']['event_id'];
		$this->loadModel('Event');
		$this->Event->Behaviors->detach('SysLogLogable.SysLogLogable');
		$this->Event->recursive = -1;
		$this->Event->id = $eventId;
		$this->Event->read();
		// Send those away that shouldn't be able to see this
		if (!$this->_isSiteAdmin()) {
			if ((($this->Event->data['Event']['orgc'] != $this->Auth->user('org')) && ($this->Auth->user('org') != $this->ShadowAttribute->data['ShadowAttribute']['org'])) || (!$this->userRole['perm_modify'])) {
				$this->Session->setFlash('You don\'t have permission to do that');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
			}
		}
		$this->ShadowAttribute->delete($id, $cascade = false);
		$this->_setProposalLock($eventId, false);
		$this->Session->setFlash(__('Proposed change discarded', true), 'default', array());
		$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
	}

/**
 * add method
 *
 * @return void
 *
 * @throws NotFoundException // TODO Exception
 */
	public function add($eventId = null) {
		$event = $this->ShadowAttribute->Event->find('first', array(
				'conditions' => array('Event.id' => $eventId),
				'recursive' => -1,
				'fields' => array('id', 'orgc', 'distribution', 'org'),
		));
		if ((($event['Event']['distribution'] == 0 && $event['Event']['org'] != $this->Auth->user('org'))) || ($event['Event']['orgc'] == $this->Auth->user('org'))) {
			$this->Session->setFlash(__('Invalid Event.'));
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		}
		if ($this->request->is('post')) {
				
			// Give error if someone tried to submit a attribute with attachment or malware-sample type.
			// TODO change behavior attachment options - this is bad ... it should rather by a messagebox or should be filtered out on the view level
			if (isset($this->request->data['ShadowAttribute']['type']) && $this->ShadowAttribute->typeIsAttachment($this->request->data['ShadowAttribute']['type'])) {
				$this->Session->setFlash(__('Attribute has not been added: attachments are added by "Add attachment" button', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
			}
			$temp = $this->_getEventData($this->request->data['ShadowAttribute']['event_id']);
			$event_uuid = $temp['uuid'];
			$event_org = $temp['orgc'];
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
					$this->request->data['ShadowAttribute']['org'] = $this->Auth->user('org');
					$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
					$this->request->data['ShadowAttribute']['event_org'] = $event_org;
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
					$this->Session->setFlash(__('The lines' . $successes . ' have been saved', true));
					$this->__sendProposalAlertEmail($eventId);
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
				$this->request->data['ShadowAttribute']['org'] = $this->Auth->user('org');
				$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
				$this->request->data['ShadowAttribute']['event_org'] = $event_org;
				if ($this->ShadowAttribute->save($this->request->data)) {
					$this->__sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id']);
					// inform the user and redirect
					$this->Session->setFlash(__('The proposal has been saved'));
					$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
				} else {
					if (!CakeSession::read('Message.flash')) {
						$this->Session->setFlash(__('The attribute could not be saved. Please, try again.'));
					}
				}
			}
		} else {
			// set the event_id in the form
			$this->request->data['ShadowAttribute']['event_id'] = $eventId;
		}

		// combobox for types
		$types = array_keys($this->ShadowAttribute->typeDefinitions);
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobos for categories
		$categories = $this->ShadowAttribute->validate['category']['rule'][1];
		array_pop($categories);
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', compact('categories'));
		// combobox for distribution
		$count = 0;

		$this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);
	}

	public function download($id = null) {
		$this->ShadowAttribute->id = $id;
		if (!$this->ShadowAttribute->exists()) {
			throw new NotFoundException(__('Invalid ShadowAttribute'));
		}

		$this->ShadowAttribute->read();
		$path = APP . "files" . DS . $this->ShadowAttribute->data['ShadowAttribute']['event_id'] . DS . 'shadow' . DS;
		$file = $this->ShadowAttribute->data['ShadowAttribute']['id'];
		$filename = '';
		if ('attachment' == $this->ShadowAttribute->data['ShadowAttribute']['type']) {
			$filename = $this->ShadowAttribute->data['ShadowAttribute']['value'];
			$fileExt = pathinfo($filename, PATHINFO_EXTENSION);
			$filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
		} elseif ('malware-sample' == $this->ShadowAttribute->data['ShadowAttribute']['type']) {
			$filenameHash = explode('|', $this->ShadowAttribute->data['ShadowAttribute']['value']);
			$filename = $filenameHash[0];
			$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
			$fileExt = "zip";
		} else {
			throw new NotFoundException(__('ShadowAttribute not an attachment or malware-sample'));
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
				'fields' => array('id', 'orgc', 'distribution', 'org'),
		));
		if ((($event['Event']['distribution'] == 0 && $event['Event']['org'] != $this->Auth->user('org'))) || ($event['Event']['orgc'] == $this->Auth->user('org'))) {
			$this->Session->setFlash(__('Invalid Event.'));
			$this->redirect(array('controller' => 'events', 'action' => 'index'));
		}
		if ($this->request->is('post')) {
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
			$temp = $this->_getEventData($this->request->data['ShadowAttribute']['event_id']);
			$event_uuid = $temp['uuid'];
			$event_org = $temp['orgc'];
			// save the file-info in the database
			$this->ShadowAttribute->create();
			if ($this->request->data['ShadowAttribute']['malware']) {
				$this->request->data['ShadowAttribute']['type'] = "malware-sample";
				// Validate filename
				if (!preg_match('@^[\w-,\s]+\.[A-Za-z0-9_]{2,4}$@', $filename)) throw new Exception ('Filename not allowed');
				$this->request->data['ShadowAttribute']['value'] = $filename . '|' . $tmpfile->md5(); // TODO gives problems with bigger files
				$this->request->data['ShadowAttribute']['to_ids'] = 1; // LATER let user choose to send this to IDS
			} else {
				$this->request->data['ShadowAttribute']['type'] = "attachment";
				// Validate filename
				if (!preg_match('@^[\w-,\s]+\.[A-Za-z0-9_]{2,4}$@', $filename)) throw new Exception ('Filename not allowed');
				$this->request->data['ShadowAttribute']['value'] = $filename;
				$this->request->data['ShadowAttribute']['to_ids'] = 0;
			}
			$this->request->data['ShadowAttribute']['uuid'] = String::uuid();
			$this->request->data['ShadowAttribute']['batch_import'] = 0;
			$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
			$this->request->data['ShadowAttribute']['org'] = $this->Auth->user('org');
			$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
			$this->request->data['ShadowAttribute']['event_org'] = $event_org;
			if ($this->ShadowAttribute->save($this->request->data)) {
				$this->__sendProposalAlertEmail($eventId);
			} else {
				$this->Session->setFlash(__('The ShadowAttribute could not be saved. Did you already upload this file?'));
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
			}

			// no errors in file upload, entry already in db, now move the file where needed and zip it if required.
			// no sanitization is required on the filename, path or type as we save
			// create directory structure
			if (PHP_OS == 'WINNT') {
				$rootDir = APP . "files" . DS . $this->request->data['ShadowAttribute']['event_id'] . DS . "shadow";
			} else {
				$rootDir = APP . DS . "files" . DS . $this->request->data['ShadowAttribute']['event_id'] . DS . "shadow";
			}
			$dir = new Folder($rootDir, true);
			// move the file to the correct location
			$destpath = $rootDir . DS . $this->ShadowAttribute->id; // id of the new ShadowAttribute in the database
			$file = new File ($destpath);
			$zipfile = new File ($destpath . '.zip');
			$fileInZip = new File($rootDir . DS . $filename); // FIXME do sanitization of the filename

			if ($file->exists() || $zipfile->exists() || $fileInZip->exists()) {
				// this should never happen as the ShadowAttribute id should be unique
				$this->Session->setFlash(__('Attachment with this name already exist in this event.', true), 'default', array(), 'error');
				// remove the entry from the database
				$this->ShadowAttribute->delete();
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
			}
			if (!move_uploaded_file($tmpfile->path, $file->path)) {
				$this->Session->setFlash(__('Problem with uploading attachment. Cannot move it to its final location.', true), 'default', array(), 'error');
				// remove the entry from the database
				$this->ShadowAttribute->delete();
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
			}

			// zip and password protect the malware files
			if ($this->request->data['ShadowAttribute']['malware']) {
				// TODO check if CakePHP has no easy/safe wrapper to execute commands
				$execRetval = '';
				$execOutput = array();
				rename($file->path, $fileInZip->path); // TODO check if no workaround exists for the current filtering mechanisms
				if (PHP_OS == 'WINNT') {
					exec("zip -j -P infected " . $zipfile->path . ' "' . $fileInZip->path . '"', $execOutput, $execRetval);
				} else {
					exec("zip -j -P infected " . $zipfile->path . ' "' . addslashes($fileInZip->path) . '"', $execOutput, $execRetval);
				}
				if ($execRetval != 0) {	// not EXIT_SUCCESS
					$this->Session->setFlash(__('Problem with zipping the attachment. Please report to administrator. ' . $execOutput, true), 'default', array(), 'error');
					// remove the entry from the database
					$this->ShadowAttribute->delete();
					$fileInZip->delete();
					$file->delete();
					$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));
				};
				$fileInZip->delete();	// delete the original not-zipped-file
				rename($zipfile->path, $file->path); // rename the .zip to .nothing
			}

			// everything is done, now redirect to event view
			$this->Session->setFlash(__('The attachment has been uploaded'));
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['ShadowAttribute']['event_id']));

		} else {
			// set the event_id in the form
			$this->request->data['ShadowAttribute']['event_id'] = $eventId;
		}

		// combobox for categories
		$categories = $this->ShadowAttribute->validate['category']['rule'][1];
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
			if ((($this->Attribute->data['Attribute']['distribution'] == 0 && $this->Attribute->data['Event']['org'] != $this->Auth->user('org'))) || ($this->Attribute->data['Event']['orgc'] == $this->Auth->user('org'))) {
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
			$event_org = $temp['orgc'];
			$this->request->data['ShadowAttribute']['old_id'] = $existingAttribute['Attribute']['id'];
			$this->request->data['ShadowAttribute']['uuid'] = $existingAttribute['Attribute']['uuid'];
			$this->request->data['ShadowAttribute']['event_id'] = $existingAttribute['Attribute']['event_id'];
			$this->request->data['ShadowAttribute']['event_uuid'] = $event_uuid;
			$this->request->data['ShadowAttribute']['event_org'] = $event_org;
			if ($attachment) $this->request->data['ShadowAttribute']['value'] = $existingAttribute['Attribute']['value'];
			if ($attachment) $this->request->data['ShadowAttribute']['type'] = $existingAttribute['Attribute']['type'];
			$this->request->data['ShadowAttribute']['org'] =  $this->Auth->user('org');
			$this->request->data['ShadowAttribute']['email'] = $this->Auth->user('email');
			$fieldList = array('category', 'type', 'value1', 'value2', 'to_ids', 'value', 'org');
			if ($this->ShadowAttribute->save($this->request->data)) {
				$this->__sendProposalAlertEmail($this->request->data['ShadowAttribute']['event_id']);
				$this->Session->setFlash(__('The proposed Attribute has been saved'));
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
		$categories = $this->ShadowAttribute->validate['category']['rule'][1];
		array_pop($categories); // remove that last empty/space option
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', $categories);

		$this->set('attrDescriptions', $this->ShadowAttribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->ShadowAttribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->ShadowAttribute->categoryDefinitions);
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
		
		$this->loadModel('User');
		$this->User->recursive = -1;
		$orgMembers = array();
		$temp = $this->User->findAllByOrg($event['Event']['orgc'], array('email', 'gpgkey', 'contactalert', 'id'));
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
		$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));	// , 'debug' => true
		$gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
		$bodySigned = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
		// Add the GPG key of the user as attachment
		// LATER sign the attached GPG key
		if (null != ($this->Auth->user('gpgkey'))) {
			// save the gpg key to a temporary file
			$tmpfname = tempnam(TMP, "GPGkey");
			$handle = fopen($tmpfname, "w");
			fwrite($handle, $this->Auth->user('gpgkey'));
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
					$gpg = new Crypt_GPG(array('homedir' => Configure::read('GnuPG.homedir')));
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
			$this->Email->subject = "[" . Configure::read('MISP.org') . " " . Configure::read('MISP.name') . "] Proposal to event #" . $id;
			$this->Email->template = 'body';
			$this->Email->sendAs = 'text';		// both text or html
			$this->set('body', $bodyEncSig);
			// Add the GPG key of the user as attachment
			// LATER sign the attached GPG key
			if (null != ($this->Auth->user('gpgkey'))) {
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
	}
	
	public function index() {
		$conditions = null;
		if (!$this->_isSiteAdmin()) {
			$conditions = array('Event.org =' => $this->Auth->user('org'));
		}
		$this->paginate = array(
				'conditions' => $conditions,
				'fields' => array('id', 'org', 'old_id'),
				'contain' => array(
						'Event' => array(
								'fields' => array('id', 'org', 'info', 'orgc'),
						),
				),
				'recursive' => 1	
		);
		$this->set('shadowAttributes', $this->paginate());
	}
	
	public function eventIndex() {
		$result = $this->ShadowAttribute->find('all', array(
			'fields' => array('event_id'),
			'group' => 'event_id',
			'conditions' => array(
				'ShadowAttribute.event_org =' => $this->Auth->user('org'),			
		)));
		$this->loadModel('Event');
		foreach ($result as $eventId) {
			
		}
	}
	
	private function _getEventData($event_id) {
		$this->loadModel('Event');
		$this->Event->recursive = -1;
		$this->Event->read(array('id', 'uuid', 'orgc'), $event_id);
		return $this->Event->data['Event'];
	} 
	
	// takes a uuid and finds all proposals that belong to an event with the given uuid. These are then returned. 
	public function getProposalsByUuid($uuid) {
		if (!$this->_isRest()) {
			throw new MethodNotAllowedException(__('This feature is only available for REST users'));
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
}
