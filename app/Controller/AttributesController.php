<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

/**
 * Attributes Controller
 *
 * @property Attribute $Attribute
 */
class AttributesController extends AppController {

	public $components = array('Security', 'RequestHandler');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
	);

	public $helpers = array('Js' => array('Jquery'));

	public function beforeFilter() {
		parent::beforeFilter();

		// permit reuse of CSRF tokens on the search page.
		if ('search' == $this->request->params['action']) {
			$this->Security->csrfUseOnce = false;
		}
		$this->Security->validatePost = true;

		// convert uuid to id if present in the url, and overwrite id field
		if (isset($this->params->query['uuid'])) {
			$params = array(
					'conditions' => array('Attribute.uuid' => $this->params->query['uuid']),
					'recursive' => 0,
					'fields' => 'Attribute.id'
					);
			$result = $this->Attribute->find('first', $params);
			if (isset($result['Attribute']) && isset($result['Attribute']['id'])) {
				$id = $result['Attribute']['id'];
				$this->params->addParams(array('pass' => array($id))); // FIXME find better way to change id variable if uuid is found. params->url and params->here is not modified accordingly now
			}
		}

	// do not show private to other orgs
		// if not admin or own org, check private as well..
		if (!$this->_IsSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate,array(
			'conditions' =>
					array('OR' =>
							array(
								'Event.org =' => $this->Auth->user('org'),
								'AND' => array(
										'Attribute.distribution' > 0,
										'Event.distribution' > 0,
			)))));
		}

/* We want to show this outside now as discussed with Christophe. Still not pushable, but anything should be pullable that's visible
		// do not show cluster outside server
		if ($this->_isRest()) {
				$this->paginate = Set::merge($this->paginate,array(
				'conditions' =>
						array("AND" => array('Event.cluster !=' => true),array('Attribute.cluster !=' => true)),
						//array("AND" => array(array('Event.private !=' => 2))),
				));
		}
		*/
	}

/**
 * index method
 *
 * @return void
 *
 */
	public function index() {
		$this->Attribute->recursive = 0;
		$this->set('isSearch', 0);

		$this->set('attributes', $this->paginate());

		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
	}

/**
 * add method
 *
 * @return void
 *
 * @throws NotFoundException // TODO Exception
 */
	public function add($eventId = null) {
		if ($this->request->is('post')) {
			$this->loadModel('Event');
			$date = new DateTime();
			// Give error if someone tried to submit a attribute with attachment or malware-sample type.
			// TODO change behavior attachment options - this is bad ... it should rather by a messagebox or should be filtered out on the view level
			if (isset($this->request->data['Attribute']['type']) && $this->Attribute->typeIsAttachment($this->request->data['Attribute']['type'])) {
				$this->Session->setFlash(__('Attribute has not been added: attachments are added by "Add attachment" button', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
			}

			// remove the published flag from the event
			$this->Event->recursive = -1;
			$this->Event->read(null, $this->request->data['Attribute']['event_id']);
			$this->Event->set('timestamp', $date->getTimestamp());
			$this->Event->set('published', 0);
			$this->Event->save($this->Event->data, array('fieldList' => array('published', 'timestamp', 'info')));

			//
			// multiple attributes in batch import
			//
			if ((isset($this->request->data['Attribute']['batch_import']) && $this->request->data['Attribute']['batch_import'] == 1)) {
				// make array from value field
				$attributes = explode("\n", $this->request->data['Attribute']['value']);

				$fails = "";	// will be used to keep a list of the lines that failed or succeeded
				$successes = "";
				// TODO loop-holes,
				// the value null value thing
				foreach ($attributes as $key => $attribute) {
					$attribute = trim($attribute);
					if (strlen($attribute) == 0)
					continue; // don't do anything for empty lines

					$this->Attribute->create();
					$this->request->data['Attribute']['value'] = $attribute; // set the value as the content of the single line
					// TODO loop-holes,
					// there seems to be a loop-hole in misp here
					// be it an create and not an update
					$this->Attribute->id = null;
					if ($this->Attribute->save($this->request->data)) {
						$successes .= " " . ($key + 1);
					} else {
						$fails .= " " . ($key + 1);
						//debug(CakeSession::read('Message.flash'));
						//	debug(tru);
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
				}

				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));

			} else {
				if (isset($this->request->data['Attribute']['uuid'])) {	// TODO here we should start RESTful dialog
					// check if the uuid already exists and also save the existing attribute for further checks
					$existingAttribute = null;
					$existingAttribute = $this->Attribute->find('first', array('conditions' => array('Attribute.uuid' => $this->request->data['Attribute']['uuid'])));
					//$existingAttributeCount = $this->Attribute->find('count', array('conditions' => array('Attribute.uuid' => $this->request->data['Attribute']['uuid'])));
					if ($existingAttribute) {
						// TODO RESTfull, set responce location header..so client can find right URL to edit
						$this->response->header('Location', Configure::read('CyDefSIG.baseurl') . '/attributes/' . $existingAttribute['Attribute']['id']);
						$this->response->send();
						$this->view($this->Attribute->getId());
						$this->render('view');
						return false;
					} else {
						// if the attribute doesn't exist yet, check whether it has a timestamp - if yes, it's from a push, keep the timestamp we had, if no create a timestamp
						if (!isset($this->request->data['Attribute']['timestamp'])) {
							$this->request->data['Attribute']['timestamp'] = $date->getTimestamp();
						}
					}
				} else {
					if (!isset($this->request->data['Attribute']['timestamp'])) {
						$this->request->data['Attribute']['timestamp'] = $date->getTimestamp();
					}
				}

				//
				// single attribute
				//
				// create the attribute
				$this->Attribute->create();

				$savedId = $this->Attribute->getId();

				if ($this->Attribute->save($this->request->data)) {
					if ($this->_isRest()) {
						// REST users want to see the newly created attribute
						$this->view($this->Attribute->getId());
						$this->render('view');
					} else {
						// inform the user and redirect
						$this->Session->setFlash(__('The attribute has been saved'));
						$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
					}
				} else {
					if ($this->_isRest()) { // TODO return error if REST
						// REST users want to see the failed attribute
						$this->view($savedId);
						$this->render('view');
					} else {
						if (!CakeSession::read('Message.flash')) {
							$this->Session->setFlash(__('The attribute could not be saved. Please, try again.'));
						}
					}
				}
			}
		} else {
			// set the event_id in the form
			$this->request->data['Attribute']['event_id'] = $eventId;
		}

		// combobox for types
		$types = array_keys($this->Attribute->typeDefinitions);
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobos for categories
		$categories = $this->Attribute->validate['category']['rule'][1];
		array_pop($categories);
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', compact('categories'));
		$this->loadModel('Event');
		$events = $this->Event->findById($eventId);
		$maxDist = $events['Event']['distribution'];
		$this->set('maxDist', $maxDist);
		// combobox for distribution
		$count = 0;
		$distributionsBeforeCut = array_keys($this->Attribute->distributionDescriptions);
		if (isset($maxDist)) {
			foreach ($distributionsBeforeCut as $current) {
				$distributions[$count] = $current;
				if ($distributions[$count] == $maxDist) break;
				$count++;
			}
		} else {
			$distributions = array_keys($this->Attribute->distributionDescriptions);
		}
		$distributions = $this->_arrayToValuesIndexArray($distributions);
		$this->set('distributions', $distributions);
		// tooltip for distribution
		$this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);

		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
	}

	public function download($id = null) {
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}

		$this->Attribute->read();
		$path = APP . "files" . DS . $this->Attribute->data['Attribute']['event_id'] . DS;
		$file = $this->Attribute->data['Attribute']['id'];
		$filename = '';
		if ('attachment' == $this->Attribute->data['Attribute']['type']) {
			$filename = $this->Attribute->data['Attribute']['value'];
			$fileExt = pathinfo($filename, PATHINFO_EXTENSION);
			$filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
		} elseif ('malware-sample' == $this->Attribute->data['Attribute']['type']) {
			$filenameHash = explode('|', $this->Attribute->data['Attribute']['value']);
			$filename = $filenameHash[0];
			$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
			$fileExt = "zip";
		} else {
			throw new NotFoundException(__('Attribute not an attachment or malware-sample'));
		}

		$this->viewClass = 'Media';
		$params = array(
					'id'		=> $file,
					'name'		=> $filename,
					'extension' => $fileExt,
					'download'	=> true,
					'path'		=> $path
		);
		$this->set($params);
	}

/**
 * add_attachment method
 *
 * @return void
 * @throws InternalErrorException
 */
	public function add_attachment($eventId = null) {
		if ($this->request->is('post')) {
			$this->loadModel('Event');
			// Check if there were problems with the file upload
			// only keep the last part of the filename, this should prevent directory attacks
			$filename = basename($this->request->data['Attribute']['value']['name']);
			$tmpfile = new File($this->request->data['Attribute']['value']['tmp_name']);
			if ((isset($this->request->data['Attribute']['value']['error']) && $this->request->data['Attribute']['value']['error'] == 0) ||
					(!empty( $this->request->data['Attribute']['value']['tmp_name']) && $this->request->data['Attribute']['value']['tmp_name'] != 'none')
			) {
				if (!is_uploaded_file($tmpfile->path))
					throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
			} else {
				$this->Session->setFlash(__('There was a problem to upload the file.', true), 'default', array(), 'error');
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
			}

			// remove the published flag from the event
			$this->Event->id = $this->request->data['Attribute']['event_id'];
			$this->Event->saveField('published', 0);
			// save the file-info in the database
			$this->Attribute->create();
			if ($this->request->data['Attribute']['malware']) {
				$this->request->data['Attribute']['type'] = "malware-sample";
				// Validate filename
				if (!preg_match('@^[\w-,\s]+\.[A-Za-z0-9_]{2,4}$@', $filename)) throw new Exception ('Filename not allowed');
				$this->request->data['Attribute']['value'] = $filename . '|' . $tmpfile->md5(); // TODO gives problems with bigger files
				$this->request->data['Attribute']['to_ids'] = 1; // LATER let user choose to send this to IDS
			} else {
				$this->request->data['Attribute']['type'] = "attachment";
				// Validate filename
				if (!preg_match('@^[\w-,\s]+\.[A-Za-z0-9_]{2,4}$@', $filename)) throw new Exception ('Filename not allowed');
				$this->request->data['Attribute']['value'] = $filename;
				$this->request->data['Attribute']['to_ids'] = 0;
			}
			$this->request->data['Attribute']['uuid'] = String::uuid();
			$this->request->data['Attribute']['batch_import'] = 0;

			if ($this->Attribute->save($this->request->data)) {
				// attribute saved correctly in the db
			} else {
				$this->Session->setFlash(__('The attribute could not be saved. Did you already upload this file?'));
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
			}

			// no errors in file upload, entry already in db, now move the file where needed and zip it if required.
			// no sanitization is required on the filename, path or type as we save
			// create directory structure
			if (PHP_OS == 'WINNT') {
				$rootDir = APP . "files" . DS . $this->request->data['Attribute']['event_id'];
			} else {
				$rootDir = APP . DS . "files" . DS . $this->request->data['Attribute']['event_id'];
			}
			$dir = new Folder($rootDir, true);
			// move the file to the correct location
			$destpath = $rootDir . DS . $this->Attribute->id; // id of the new attribute in the database
			$file = new File ($destpath);
			$zipfile = new File ($destpath . '.zip');
			$fileInZip = new File($rootDir . DS . $filename); // FIXME do sanitization of the filename

			if ($file->exists() || $zipfile->exists() || $fileInZip->exists()) {
				// this should never happen as the attribute id should be unique
				$this->Session->setFlash(__('Attachment with this name already exist in this event.', true), 'default', array(), 'error');
				// remove the entry from the database
				$this->Attribute->delete();
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
			}
			if (!move_uploaded_file($tmpfile->path, $file->path)) {
				$this->Session->setFlash(__('Problem with uploading attachment. Cannot move it to its final location.', true), 'default', array(), 'error');
				// remove the entry from the database
				$this->Attribute->delete();
				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
			}

			// zip and password protect the malware files
			if ($this->request->data['Attribute']['malware']) {
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
					$this->Attribute->delete();
					$fileInZip->delete();
					$file->delete();
					$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
				};
				$fileInZip->delete();	// delete the original not-zipped-file
				rename($zipfile->path, $file->path); // rename the .zip to .nothing
			}

			// everything is done, now redirect to event view
			$this->Session->setFlash(__('The attachment has been uploaded'));
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));

		} else {
			// set the event_id in the form
			$this->request->data['Attribute']['event_id'] = $eventId;
			$this->loadModel('Event');
			$events = $this->Event->findById($eventId);
			$maxDist = $events['Event']['distribution'];
			$this->set('maxDist', $maxDist);
		}

		// combobos for categories
		$categories = $this->Attribute->validate['category']['rule'][1];
		// just get them with attachments..
		$selectedCategories = array();
		foreach ($categories as $category) {
			if (isset($this->Attribute->categoryDefinitions[$category])) {
				$types = $this->Attribute->categoryDefinitions[$category]['types'];
				$alreadySet = false;
				foreach ($types as $type) {
					if ($this->Attribute->typeIsAttachment($type) && !$alreadySet) {
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

		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);

		$this->set('zippedDefinitions', $this->Attribute->zippedDefinitions);
		$this->set('uploadDefinitions', $this->Attribute->uploadDefinitions);

		// combobox for distribution
		if (isset($maxDist)) {
			$distributionsBeforeCut = array_keys($this->Attribute->distributionDescriptions);
			$count = 0;
			foreach ($distributionsBeforeCut as $current) {
				$distributions[$count] = $current;
				if ($distributions[$count] == $maxDist)break;
				$count++;
			}
		} else {
			$distributions = array_keys($this->Attribute->distributionDescriptions);
		}
		$distributions = $this->_arrayToValuesIndexArray($distributions);
		$this->set('distributions', $distributions);
		// tooltip for distribution
		$this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);
	}

/**
 * edit method
 *
 * @param string $id
 * @return void
 * @throws NotFoundException
 */
	public function edit($id = null) {
		$this->Attribute->id = $id;
		$date = new DateTime();
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$this->Attribute->read();
		//set stuff to fix undefined index: uuid
		if (!$this->_isRest()) {
			$uuid = $this->Attribute->data['Attribute']['uuid'];
		}
		if (!$this->_IsSiteAdmin()) {
			// check for non-private and re-read
			if (($this->Attribute->data['Event']['org'] != $this->Auth->user('org')) || (($this->Attribute->data['Event']['org'] == $this->Auth->user('org')) && ($this->Attribute->data['Event']['user_id'] != $this->Auth->user('id')) && (!$this->checkAction('prem_modify') || !$this->checkRole() || !$this->checkAction('perm_publish')))) {
				$this->Session->setFlash(__('Invalid attribute.'));
				$this->redirect(array('controller' => 'events', 'action' => 'index'));
			}
		}

		$eventId = $this->Attribute->data['Attribute']['event_id'];
		if ('attachment' == $this->Attribute->data['Attribute']['type'] ||
			'malware-sample' == $this->Attribute->data['Attribute']['type'] ) {
			$this->set('attachment', true);
			//	TODO we should ensure 'value' cannot be changed here and not only on a view level (because of the associated file)
			//	$this->Session->setFlash(__('You cannot edit attachment attributes.', true), 'default', array(), 'error');
			//	$this->redirect(array('controller' => 'events', 'action' => 'view', $old_attribute['Event']['id']));
		} else {
			$this->set('attachment', false);
		}
		if ($this->request->is('post') || $this->request->is('put')) {

			// reposition to get the attribute.id with given uuid
			// Notice (8): Undefined index: uuid [APP/Controller/AttributesController.php, line 502]
			// Fixed - uuid was not passed back from the form since it's not a field. Set the uuid in a variable for non rest users, rest should have uuid.
			// Generally all of this should be _isRest() only, but that's something for later to think about
			if ($this->_isRest()) {
				$existingAttribute = $this->Attribute->findByUuid($this->request->data['Attribute']['uuid']);
			} else {
				$existingAttribute = $this->Attribute->findByUuid($uuid);
			}
			if (count($existingAttribute)) {
				$this->request->data['Attribute']['id'] = $existingAttribute['Attribute']['id'];
			}
			// check if the attribute has a timestamp already set (from a previous instance that is trying to edit via synchronisation)
			if (isset($this->request->data['Attribute']['timestamp'])) {
				// check which attribute is newer
				if ($this->request->data['Attribute']['timestamp'] > $existingAttribute['Attribute']['timestamp']) {
					// carry on with adding this attribute - Don't forget! if orgc!=user org, create shadow attribute, not attribute!
				} else {
					// the old one is newer or the same, replace the request's attribute with the old one
					$this->request->data['Attribute'] = $existingAttribute['Attribute'];
				}
			} else {
				$this->request->data['Attribute']['timestamp'] = $date->getTimestamp();
			}
			$fieldList = array('category', 'type', 'value1', 'value2', 'to_ids', 'private', 'cluster', 'value', 'timestamp');

			$this->loadModel('Event');
			$this->Event->id = $eventId;

			// enabling / disabling the distribution field in the edit view based on whether user's org == orgc in the event
			$this->Event->read();
			if ($this->Attribute->save($this->request->data)) {
				$this->Session->setFlash(__('The attribute has been saved'));
				// remove the published flag from the event
				$this->Event->set('timestamp', $date->getTimestamp());
				$this->Event->set('published', 0);
				$this->Event->save($this->Event->data, array('fieldList' => array('published', 'timestamp', 'info')));

				if ($this->_isRest()) {
					// REST users want to see the newly created event
					$this->view($this->Attribute->getId());
					$this->render('view');
				} else {
					$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
				}
			} else {
				if (!CakeSession::read('Message.flash')) {
					$this->Session->setFlash(__('The attribute could not be saved. Please, try again.'));
				} else {
					$this->request->data = $this->Attribute->read(null, $id);
				}
			}
		} else {
			$this->request->data = $this->Attribute->read(null, $id);
		}
		$this->set('attribute', $this->request->data);

		// enabling / disabling the distribution field in the edit view based on whether user's org == orgc in the event
		$this->loadModel('Event');
		$this->Event->id = $eventId;
		$this->Event->read();
		// needed for RBAC
		// combobox for types
		$types = array_keys($this->Attribute->typeDefinitions);
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobox for categories
		$categories = $this->Attribute->validate['category']['rule'][1];
		array_pop($categories); // remove that last empty/space option
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', $categories);

		$events = $this->Event->findById($eventId);
		$maxDist = $events['Event']['distribution'];
		$this->set('maxDist', $maxDist);
		// combobox for distribution
		if (isset($maxDist)) {
			$distributionsBeforeCut = array_keys($this->Attribute->distributionDescriptions);
			$count = 0;
			foreach ($distributionsBeforeCut as $current) {
				$distributions[$count] = $current;
				if ($distributions[$count] == $maxDist)break;
				$count++;
			}
		} else {
			$distributions = array_keys($this->Attribute->distributionDescriptions);
		}
		$distributions = $this->_arrayToValuesIndexArray($distributions);
		$this->set('distributions', $distributions);
		// tooltip for distribution
		$this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);
		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
	}

/**
 * delete method
 *
 * @param string $id
 * @return void
 * @throws MethodNotAllowedException
 * @throws NotFoundException
 *
 * and is able to delete w/o question
 */
	public function delete($id = null) {
		if (!$this->request->is('post') && !$this->_isRest()) {
			throw new MethodNotAllowedException();
		}

		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}

		if ('true' == Configure::read('CyDefSIG.sync')) {
			// find the uuid
			$result = $this->Attribute->findById($id);
			$uuid = $result['Attribute']['uuid'];
		}

		// attachment will be deleted with the beforeDelete() function in the Model
		if ($this->Attribute->delete()) {
			// delete the attribute from remote servers
			if ('true' == Configure::read('CyDefSIG.sync')) {
				// find the uuid
				$this->__deleteAttributeFromServers($uuid);
			}

			$this->Session->setFlash(__('Attribute deleted'));
		} else {
			$this->Session->setFlash(__('Attribute was not deleted'));
		}

		if (!$this->_isRest()) $this->redirect($this->referer());	// TODO check
		else $this->redirect(array('action' => 'index'));
	}

/**
 * Deletes this specific attribute from all remote servers
 * TODO move this to a component(?)
 */
	private function __deleteAttributeFromServers($uuid) {

		// get a list of the servers
		$this->loadModel('Server');
		$servers = $this->Server->find('all', array());

		// iterate over the servers and upload the attribute
		if (empty($servers))
			return;

		App::uses('HttpSocket', 'Network/Http');
		$HttpSocket = new HttpSocket();
		foreach ($servers as &$server) {
			$this->Attribute->deleteAttributeFromServer($uuid, $server, $HttpSocket);
		}
	}

	public function search() {
		$fullAddress = '/attributes/search';

		if ($this->request->here == $fullAddress) {

			$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
			$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
			$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
			// reset the paginate_conditions
			$this->Session->write('paginate_conditions',array());

			if ($this->request->is('post') && ($this->request->here == $fullAddress)) {
				$keyword = $this->request->data['Attribute']['keyword'];
				$keyword2 = $this->request->data['Attribute']['keyword2'];
				$org = $this->request->data['Attribute']['org'];
				$type = $this->request->data['Attribute']['type'];
				$category = $this->request->data['Attribute']['category'];
				$this->set('keywordSearch', $keyword);
				$keyWordText = null;
				$keyWordText2 = null;
				$this->set('typeSearch', $type);
				$this->set('isSearch', 1);
				$this->set('categorySearch', $category);
				// search the db
				$conditions = array();

				// search on the value field
				if (isset($keyword)) {
					$keywordArray = explode("\n", $keyword);
					$this->set('keywordArray', $keywordArray);
					$i = 1;
					$temp = array();
					foreach ($keywordArray as $keywordArrayElement) {
						$saveWord = trim($keywordArrayElement);
						$keywordArrayElement = '%' . trim($keywordArrayElement) . '%';
						if ($keywordArrayElement != '%%') array_push($temp, array('Attribute.value LIKE' => $keywordArrayElement));
						if ($i == 1 && $saveWord != '') $keyWordText = $saveWord;
						else if (($i > 1 && $i < 10) && $saveWord != '') $keyWordText = $keyWordText . ', ' . $saveWord;
						else if ($i == 10 && $saveWord != '') $keyWordText = $keyWordText . ' and several other keywords';
						$i++;
					}
					$this->set('keywordSearch', $keyWordText);
					if (!empty($temp)) {
						if (count($temp) == 1) {
							$conditions['Attribute.value LIKE'] = '%' . $keyWordText . '%';
						} else {
							$conditions['OR'] = $temp;
						}
					}
				}

				// event IDs to be excluded
				if (isset($keyword2)) {
					$keywordArray2 = explode("\n", $keyword2);
					$i = 1;
					$temp = array();
					foreach ($keywordArray2 as $keywordArrayElement) {
						$saveWord = trim($keywordArrayElement);
						if (!is_numeric($saveWord) || $saveWord < 1) continue;
						array_push($temp, array('Attribute.event_id !=' => $keywordArrayElement));
						if ($i == 1 && $saveWord != '') $keyWordText2 = $saveWord;
						else if (($i > 1 && $i < 10) && $saveWord != '') $keyWordText2 = $keyWordText2 . ', ' . $saveWord;
						else if ($i == 10 && $saveWord != '') $keyWordText2 = $keyWordText2 . ' and several other events';
						$i++;
					}
					$this->set('keywordSearch2', $keyWordText2);
					if (!empty($temp)) {
						if (count($temp) == 1) {
							$conditions['Attribute.event_id !='] = $keyWordText2;
						} else {
							$conditions['AND'] = $temp;
						}
					}
				}
				if ($type != 'ALL') {
					$conditions['Attribute.type ='] = $type;
				}
				if ($category != 'ALL') {
					$conditions['Attribute.category ='] = $category;
				}
				// organisation search field
				if (isset($org) && $org != '') {
					$org = trim($org);
					$this->set('orgSearch', $org);
					$conditions['Event.orgc ='] = $org;
				}
				$this->Attribute->recursive = 0;
				$this->paginate = array(
					'limit' => 60,
					'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 attributes?
					'conditions' => $conditions
				);
				if (!$this->_IsSiteAdmin()) {
					// merge in private conditions
					$this->paginate = Set::merge($this->paginate, array(
						'conditions' =>
							array("OR" => array(
							array('Event.org =' => $this->Auth->user('org')),
							array("AND" => array('Event.org !=' => $this->Auth->user('org')), array('Event.distribution !=' => 0), array('Attribute.distribution !=' => 0)))),
						)
					);
				}

				$idList = array();
				$attributes = $this->paginate();
				foreach ($attributes as &$attribute) {
					if (!in_array($attribute['Attribute']['event_id'], $idList)) {
						$idList[] = $attribute['Attribute']['event_id'];
					}
				}
				$this->set('attributes', $attributes);

				// and store into session
				$this->Session->write('paginate_conditions', $this->paginate);
				$this->Session->write('paginate_conditions_keyword', $keyword);
				$this->Session->write('paginate_conditions_type', $type);
				$this->Session->write('paginate_conditions_category', $category);
				$this->Session->write('search_find_idlist', $idList);

				// set the same view as the index page
				$this->render('index');
			} else {
				// no search keyword is given, show the search form

				// adding filtering by category and type
				// combobox for types
				$types = array('' => array('ALL' => 'ALL'), 'types' => array());
				$types['types'] = array_merge($types['types'], $this->_arrayToValuesIndexArray(array_keys($this->Attribute->typeDefinitions)));
				$this->set('types', $types);

				// combobox for categories
				$categories = array('' => array('ALL' => 'ALL', '' => ''), 'categories' => array());
				array_pop($this->Attribute->validate['category']['rule'][1]); // remove that last 'empty' item
				$categories['categories'] = array_merge($categories['categories'], $this->_arrayToValuesIndexArray($this->Attribute->validate['category']['rule'][1]));
				$this->set('categories', $categories);
			}
		} else {
			$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
			$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
			$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);

			// get from Session
			$keyword = $this->Session->read('paginate_conditions_keyword');
			$type = $this->Session->read('paginate_conditions_type');
			$category = $this->Session->read('paginate_conditions_category');
			$this->set('keywordSearch', $keyword);
			$this->set('typeSearch', $type);
			$this->set('isSearch', 1);
			$this->set('categorySearch', $category);

			// re-get pagination
			$this->Attribute->recursive = 0;
			$this->paginate = $this->Session->read('paginate_conditions');
			$this->set('attributes', $this->paginate());

			// set the same view as the index page
			$this->render('index');
		}
	}

	public function downloadAttributes() {
		$idList = $this->Session->read('search_find_idlist');
		$this->response->type('xml');	// set the content type
		$this->header('Content-Disposition: download; filename="misp.attribute.search.xml"');
		$this->layout = 'xml/default';
		$this->loadModel('Attribute');
		if (!isset($idList)) {
			print "No results found to export\n";
		} else {
			foreach ($idList as $listElement) {
				$put['OR'][] = array('Attribute.id' => $listElement);
			}
			$conditions['AND'][] = $put;
			//	restricting to non-private or same org if the user is not a site-admin.
			if (!$this->_isSiteAdmin()) {
				$temp = array();
				array_push($temp, array('Attribute.distribution >' => 0));
				array_push($temp, array('OR' => $distribution));
				array_push($temp, array('(SELECT events.org FROM events WHERE events.id = Attribute.event_id) LIKE' => $this->_checkOrg()));
				$put2['OR'][] = $temp;
				$conditions['AND'][] = $put2;
			}
			$params = array(
					'conditions' => $conditions, //array of conditions
					'recursive' => 0, //int
					'fields' => array('Attribute.id', 'Attribute.value'), //array of field names
					'order' => array('Attribute.id'), //string or array defining order
			);
			$attributes = $this->Attribute->find('all', $params);
			$this->set('results', $attributes);
		}
		$this->render('xml');
	}

	public function checkComposites() {
		if (!self::_isAdmin()) throw new NotFoundException();

		$this->set('fails', $this->Attribute->checkComposites());
	}
}
