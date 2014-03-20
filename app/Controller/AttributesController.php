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

	public $components = array('Security', 'RequestHandler', 'Cidr');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events
	);

	public $helpers = array('Js' => array('Jquery'));

	public function beforeFilter() {
		parent::beforeFilter();

		$this->Auth->allow('restSearch');
		$this->Auth->allow('returnAttributes');
		$this->Auth->allow('downloadAttachment');
		$this->Auth->allow('text');

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
		if (!$this->_isSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate,array(
			'conditions' =>
					array('OR' =>
							array(
								'Event.org =' => $this->Auth->user('org'),
								'AND' => array(
										'Attribute.distribution >' => 0,
										'Event.distribution >' => 0,
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
		$this->Attribute->contain = array('Event.id', 'Event.orgc', 'Event.org');
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
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('You don\'t have permissions to create attributes');
		}
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
			if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
				throw new UnauthorizedException('You do not have permission to do that.');
			}
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
						$this->response->header('Location', Configure::read('MISP.baseurl') . '/attributes/' . $existingAttribute['Attribute']['id']);
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
		// combobox for distribution
		$this->set('distributionLevels', $this->Attribute->distributionLevels);
		$this->set('currentDist', $events['Event']['distribution']); // TODO default distribution
		// tooltip for distribution
		$this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);

		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
		$this->set('published', $events['Event']['published']);
	}

	public function download($id = null) {
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$this->Attribute->read();
		if (!$this->_isSiteAdmin() &&
			$this->Auth->user('org') !=
			$this->Attribute->data['Event']['org'] &&
			($this->Attribute->data['Event']['distribution'] == 0 ||
				$this->Attribute->data['Attribute']['distribution'] == 0
			)) {
			throw new UnauthorizedException('You do not have the permission to view this event.');
		}
		$this->__downloadAttachment($this->Attribute->data['Attribute']);
	}

	private function __downloadAttachment($attribute) {
		$path = "files" . DS . $attribute['event_id'] . DS;
		$file = $attribute['id'];
		$filename = '';
		if ('attachment' == $attribute['type']) {
			$filename = $attribute['value'];
			$fileExt = pathinfo($filename, PATHINFO_EXTENSION);
			$filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
		} elseif ('malware-sample' == $attribute['type']) {
			$filenameHash = explode('|', $attribute['value']);
			$filename = $filenameHash[0];
			$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
			$fileExt = "zip";
		} else {
			throw new NotFoundException(__('Attribute not an attachment or malware-sample'));
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
		$sha256 = null;
		$sha1 = null;
		//$ssdeep = null;
		if ($this->request->is('post')) {
			$this->loadModel('Event');
			$this->Event->id = $this->request->data['Attribute']['event_id'];
			$this->Event->recursive = -1;
			$this->Event->read();
			if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
				throw new UnauthorizedException('You do not have permission to do that.');
			}
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

			// save the file-info in the database
			$this->Attribute->create();
			if ($this->request->data['Attribute']['malware']) {
				$this->request->data['Attribute']['type'] = "malware-sample";
				// Validate filename
				if (!preg_match('@^[\w\-. ]+$@', $filename)) throw new Exception ('Filename not allowed');
				$this->request->data['Attribute']['value'] = $filename . '|' . hash_file('md5', $tmpfile->path); // TODO gives problems with bigger files
				$sha256 = (hash_file('sha256', $tmpfile->path));
				$sha1 = (hash_file('sha1', $tmpfile->path));
				$this->request->data['Attribute']['to_ids'] = 1; // LATER let user choose to send this to IDS
			} else {
				$this->request->data['Attribute']['type'] = "attachment";
				// Validate filename
				if (!preg_match('@^[\w\-. ]+$@', $filename)) throw new Exception ('Filename not allowed');
				$this->request->data['Attribute']['value'] = $filename;
				$this->request->data['Attribute']['to_ids'] = 0;
			}
			$this->request->data['Attribute']['uuid'] = String::uuid();
			$this->request->data['Attribute']['batch_import'] = 0;

			if ($this->Attribute->save($this->request->data)) {
				// attribute saved correctly in the db
				// remove the published flag from the event
				$this->Event->id = $this->request->data['Attribute']['event_id'];
				$this->Event->saveField('published', 0);
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
			if ($this->request->data['Attribute']['malware']) {
				$temp = $this->request->data;
				$this->Attribute->create();
				$temp['Attribute']['type'] = 'filename|sha256';
				$temp['Attribute']['value'] = $filename . '|' .$sha256;
				$temp['Attribute']['uuid'] = String::uuid();
				$this->Attribute->save($temp, array('fieldlist' => array('value', 'type', 'category', 'event_id', 'distribution', 'to_ids', 'comment')));
				$this->Attribute->create();
				$temp['Attribute']['type'] = 'filename|sha1';
				$temp['Attribute']['value'] = $filename . '|' .$sha1;
				$temp['Attribute']['uuid'] = String::uuid();
				$this->Attribute->save($temp, array('fieldlist' => array('value', 'type', 'category', 'event_id', 'distribution', 'to_ids', 'comment')));
			}



			// everything is done, now redirect to event view
			$this->Session->setFlash(__('The attachment has been uploaded'));
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));

		} else {
			// set the event_id in the form
			$this->request->data['Attribute']['event_id'] = $eventId;
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
		$this->loadModel('Event');
		$this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);
		$this->set('distributionLevels', $this->Event->distributionLevels);
		$events = $this->Event->findById($eventId);
		$this->set('currentDist', $events['Event']['distribution']);
		$this->set('published', $events['Event']['published']);
	}

	/**
	 * Imports the CSV threatConnect file to multiple attributes
	 * @param int $id  The id of the event
	 */
	public function add_threatconnect($eventId = null) {
		if ($this->request->is('post')) {

			$this->loadModel('Event');
			$this->Event->id = $eventId;
			$this->Event->recursive = -1;
			$this->Event->read();
			if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
				throw new UnauthorizedException('You do not have permission to do that.');
			}
			//
			// File upload
			//
			// Check if there were problems with the file upload
			$tmpfile = new File($this->request->data['Attribute']['value']['tmp_name']);
			if ((isset($this->request->data['Attribute']['value']['error']) && $this->request->data['Attribute']['value']['error'] == 0) ||
			        (!empty( $this->request->data['Attribute']['value']['tmp_name']) && $this->request->data['Attribute']['value']['tmp_name'] != 'none')
			) {
			    if (!is_uploaded_file($tmpfile->path))
			        throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
			} else {
			    $this->Session->setFlash(__('There was a problem to upload the file.', true), 'default', array(), 'error');
			    $this->redirect(array('controller' => 'attributes', 'action' => 'add_threatconnect', $this->request->data['Attribute']['event_id']));
			}
			// verify mime type
			$file_info = $tmpfile->info();
			if ($file_info['mime'] != 'text/plain') {
				$this->Session->setFlash('File not in CSV format.', 'default', array(), 'error');
				$this->redirect(array('controller' => 'attributes', 'action' => 'add_threatconnect', $this->request->data['Attribute']['event_id']));
			}

			// parse uploaded csv file
			$filename = $tmpfile->path;
			$header = NULL;
			$entries = array();
			if (($handle = fopen($filename, 'r')) !== FALSE) {
				while (($row = fgetcsv($handle, 0, ',', '"')) !== FALSE) {
					if(!$header)
						$header = $row;
					else
						$entries[] = array_combine($header, $row);
				}
				fclose($handle);
			}
			// verify header of the file (first row)
			$required_headers = array('Type', 'Value', 'Confidence', 'Description', 'Source');
			
			if (count(array_intersect($header, $required_headers)) != count($required_headers)) {
				$this->Session->setFlash('Incorrect ThreatConnect headers. The minimum required headers are: '.implode(',', $required_headers), 'default', array(), 'error');
				$this->redirect(array('controller' => 'attributes', 'action' => 'add_threatconnect', $this->request->data['Attribute']['event_id']));
			}

			//
			// import attributes
			//
			$attributes = array();  // array with all the attributes we're going to save
			foreach($entries as $entry) {
				$attribute = array();
				$attribute['event_id'] = $this->request->data['Attribute']['event_id'];
				$attribute['value'] = $entry['Value'];
				$attribute['to_ids'] = ($entry['Confidence'] > 51) ? 1 : 0; // To IDS if high confidence
				$attribute['comment'] = 'ThreatConnect: ' . $entry['Description'];
				$attribute['distribution'] = '3'; // 'All communities'
				if (Configure::read('MISP.default_attribute_distribution') != null) {
					if (Configure::read('MISP.default_attribute_distribution') === 'event') {
						$attribute['distribution'] = $this->Event->data['Event']['distribution'];
					} else {
						$attribute['distribution'] = Configure::read('MISP.default_attribute_distribution');
					}
				}
				switch($entry['Type']) {
					case 'Address':
						$attribute['category'] = 'Network activity';
						$attribute['type'] = 'ip-dst';
						break;
					case 'Host':
						$attribute['category'] = 'Network activity';
						$attribute['type'] = 'domain';
						break;
					case 'EmailAddress':
						$attribute['category'] = 'Payload delivery';
						$attribute['type'] = 'email-src';
						break;
					case 'File':
						$attribute['category'] = 'Artifacts dropped';
						$attribute['value'] = strtolower($attribute['value']);
						if (preg_match("#^[0-9a-f]{32}$#", $attribute['value']))
							$attribute['type'] = 'md5';
						else if (preg_match("#^[0-9a-f]{40}$#", $attribute['value']))
						    $attribute['type'] = 'sha1';
						else if (preg_match("#^[0-9a-f]{64}$#", $attribute['value']))
						    $attribute['type'] = 'sha256';
						else
							// do not keep attributes that do not have a match
							$attribute=NULL;
						break;
					case 'URL':
						$attribute['category'] = 'Network activity';
						$attribute['type'] = 'url';
						break;
					default:
						// do not keep attributes that do not have a match
						$attribute=NULL;
				}
				// add attribute to the array that will be saved
				if ($attribute) $attributes[] = $attribute;
			}

			//
			// import source info:
			//
			// 1/ iterate over all the sources, unique
			// 2/ add uniques as 'Internal reference'
			// 3/ if url format -> 'link'
			//	else 'comment'
			$references = array();
			foreach($entries as $entry) {
				$references[$entry['Source']] = true;
			}
			$references = array_keys($references);
			// generate the Attributes
			foreach($references as $reference) {
				$attribute = array();
				$attribute['event_id'] = $this->request->data['Attribute']['event_id'];
				$attribute['category'] = 'Internal reference';
				if (preg_match('#^(http|ftp)(s)?\:\/\/((([a-z|0-9|\-]{1,25})(\.)?){2,7})($|/.*$)#i', $reference))
					$attribute['type'] = 'link';
				else
					$attribute['type'] = 'comment';
				$attribute['value'] = $reference;
				$attribute['distribution'] = 3; // 'All communities'
				// add attribute to the array that will be saved
				$attributes[] = $attribute;
			}

			//
			// finally save all the attributes at once, and continue if there are validation errors
			//
			$this->Attribute->saveMany($attributes, array('validate' => true));
			// data imported (with or without errors)
			// remove the published flag from the event
			$this->loadModel('Event');
			$this->Event->id = $this->request->data['Attribute']['event_id'];
			$this->Event->saveField('published', 0);

			// everything is done, now redirect to event view
			$this->Session->setFlash(__('The ThreatConnect data has been imported'));
			$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));

		} else {
			// set the event_id in the form
			$this->request->data['Attribute']['event_id'] = $eventId;
		}

		// form not submitted, show page
		$this->loadModel('Event');
		$events = $this->Event->findById($eventId);
		$this->set('published', $events['Event']['published']);
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
		if (!$this->_isSiteAdmin()) {
			//
			if ($this->Attribute->data['Event']['orgc'] == $this->Auth->user('org')
				&& (($this->userRole['perm_modify'] && $this->Attribute->data['Event']['user_id'] != $this->Auth->user('id'))
					|| $this->userRole['perm_modify_org'])) {
				// Allow the edit
			} else {
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
			$fieldList = array('category', 'type', 'value1', 'value2', 'to_ids', 'distribution', 'value', 'timestamp', 'comment');

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
		$this->set('published', $this->Event->data['Event']['published']);
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
		$this->set('currentDist', $this->Event->data['Event']['distribution']);
		// combobox for distribution
		$this->set('distributionLevels', $this->Attribute->distributionLevels);
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

		if ('true' == Configure::read('MISP.sync')) {
			// find the uuid
			$result = $this->Attribute->findById($id);
			$uuid = $result['Attribute']['uuid'];
		}

		// check for permissions
		if (!$this->_isSiteAdmin()) {
			$this->Attribute->read();
			if ($this->Attribute->data['Event']['locked']) {
				if ($this->_checkOrg() != $this->Attribute->data['Event']['org'] || !$this->userRole['perm_sync']) {
					throw new MethodNotAllowedException();
				}
			} else {
				if ($this->_checkOrg() != $this->Attribute->data['Event']['orgc']) {
					throw new MethodNotAllowedException();
				}
			}
		}

		// attachment will be deleted with the beforeDelete() function in the Model
		if ($this->Attribute->delete()) {
			// delete the attribute from remote servers
			if ('true' == Configure::read('MISP.sync')) {
				// find the uuid
				$this->__deleteAttributeFromServers($uuid);
			}

			// We have just deleted the attribute, let's also check if there are any shadow attributes that were attached to it and delete them
			$this->loadModel('ShadowAttribute');
			$this->ShadowAttribute->deleteAll(array('ShadowAttribute.old_id' => $id), false);
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

		// get a list of the servers with push active
		$this->loadModel('Server');
		$servers = $this->Server->find('all', array('conditions' => array('push' => 1)));

		// iterate over the servers and upload the attribute
		if (empty($servers))
			return;
		App::uses('SyncTool', 'Tools');
		foreach ($servers as &$server) {
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
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
				$ioc = $this->request->data['Attribute']['ioc'];
				$this->set('ioc', $ioc);
				$category = $this->request->data['Attribute']['category'];
				$this->set('keywordSearch', $keyword);
				$keyWordText = null;
				$keyWordText2 = null;
				$keyWordText3 = null;
				$this->set('typeSearch', $type);
				$this->set('isSearch', 1);
				$this->set('categorySearch', $category);
				// search the db
				$conditions = array();
				if ($ioc) {
					$conditions['AND'][] = array('Attribute.to_ids =' => 1);
					$conditions['AND'][] = array('Event.published =' => 1);
				}
				// search on the value field
				if (isset($keyword)) {
					$keywordArray = explode("\n", $keyword);
					$this->set('keywordArray', $keywordArray);
					$i = 1;
					$temp = array();
					$temp2 = array();
					foreach ($keywordArray as $keywordArrayElement) {
						$saveWord = trim($keywordArrayElement);
						$keywordArrayElement = '%' . trim($keywordArrayElement) . '%';
						if ($keywordArrayElement != '%%') {
							if ($keywordArrayElement[1] == '!') {
								if (preg_match('@^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$@', substr($saveWord, 2))) {
									$cidrresults = $this->Cidr->CIDR($saveWord);
									foreach ($cidrresults as $result) {
										array_push($temp2, array('Attribute.value NOT LIKE' => $result));
									}
								} else {
									array_push($temp2, array('Attribute.value NOT LIKE' => '%' . substr($keywordArrayElement, 2)));
								}
							} else {
								if (preg_match('@^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$@', $saveWord)) {
									$cidrresults = $this->Cidr->CIDR($saveWord);
									foreach ($cidrresults as $result) {
										array_push($temp, array('Attribute.value LIKE' => $result));
									}
								} else {
									array_push($temp, array('Attribute.value LIKE' => $keywordArrayElement));
								}
							}
						}
						if ($i == 1 && $saveWord != '') $keyWordText = $saveWord;
						else if (($i > 1 && $i < 10) && $saveWord != '') $keyWordText = $keyWordText . ', ' . $saveWord;
						else if ($i == 10 && $saveWord != '') $keyWordText = $keyWordText . ' and several other keywords';
						$i++;
					}
					$this->set('keywordSearch', $keyWordText);
					if (!empty($temp)) {
						$conditions['AND']['OR'] = $temp;
					}
					if (!empty($temp2)) {
						$conditions['AND'][] = $temp2;
					}

				}

				// event IDs to be excluded
				if (isset($keyword2)) {
					$keywordArray2 = explode("\n", $keyword2);
					$i = 1;
					$temp = array();
					foreach ($keywordArray2 as $keywordArrayElement) {
						$saveWord = trim($keywordArrayElement);
						if (empty($saveWord)) continue;
						if ($saveWord[0] == '!') {
							$temp[] = array('Attribute.event_id !=' => substr($saveWord, 1));
						} else {
							$temp['OR'][] = array('Attribute.event_id =' => $saveWord);
						}
						if ($i == 1 && $saveWord != '') $keyWordText2 = $saveWord;
						else if (($i > 1 && $i < 10) && $saveWord != '') $keyWordText2 = $keyWordText2 . ', ' . $saveWord;
						else if ($i == 10 && $saveWord != '') $keyWordText2 = $keyWordText2 . ' and several other events';
						$i++;
					}
					$this->set('keywordSearch2', $keyWordText2);
					if (!empty($temp)) {
						$conditions['AND'][] = $temp;
					}
				}
				if ($type != 'ALL') {
					$conditions['Attribute.type ='] = $type;
				}
				if ($category != 'ALL') {
					$conditions['Attribute.category ='] = $category;
				}
				// organisation search field
				$i = 1;
				$temp = array();
				if (isset($org)) {
					$orgArray = explode("\n", $org);
					foreach ($orgArray as $orgArrayElement) {
						$saveWord = trim($orgArrayElement);
						if (empty($saveWord)) continue;
						if ($saveWord[0] == '!') {
							$temp[] = array('Event.orgc NOT LIKE ' => '%' . substr($saveWord, 1) . '%');
						} else {
							$temp['OR'][] = array('Event.orgc LIKE ' => '%' . $saveWord . '%');
						}
					}
					if ($i == 1 && $saveWord != '') $keyWordText3 = $saveWord;
					else if (($i > 1 && $i < 10) && $saveWord != '') $keyWordText3 = $keyWordText3 . ', ' . $saveWord;
					else if ($i == 10 && $saveWord != '') $keyWordText3 = $keyWordText3 . ' and several other organisations';
					$i++;
					$this->set('orgSearch', $keyWordText3);
					if (!empty($temp)) {
						$conditions['AND'][] = $temp;
					}
				}
				$this->Attribute->recursive = 0;
				$this->paginate = array(
					'limit' => 60,
					'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 attributes?
					'conditions' => $conditions,
					'contain' => array('Event.orgc', 'Event.id', 'Event.org')
				);
				if (!$this->_isSiteAdmin()) {
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
				$attributeIdList = array();
				$attributes = $this->paginate();
				// if we searched for IOCs only, apply the whitelist to the search result!

				if ($ioc) {
					$this->loadModel('Whitelist');
					$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
				}

				foreach ($attributes as &$attribute) {
					$attributeIdList[] = $attribute['Attribute']['id'];
					if (!in_array($attribute['Attribute']['event_id'], $idList)) {
						$idList[] = $attribute['Attribute']['event_id'];
					}
				}
				$this->set('attributes', $attributes);

				// and store into session
				$this->Session->write('paginate_conditions', $this->paginate);
				$this->Session->write('paginate_conditions_keyword', $keyword);
				$this->Session->write('paginate_conditions_keyword2', $keyword2);
				$this->Session->write('paginate_conditions_org', $org);
				$this->Session->write('paginate_conditions_type', $type);
				$this->Session->write('paginate_conditions_category', $category);
				$this->Session->write('search_find_idlist', $idList);
				$this->Session->write('search_find_attributeidlist', $attributeIdList);

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
			$keyword2 = $this->Session->read('paginate_conditions_keyword2');
			$org = $this->Session->read('paginate_conditions_org');
			$type = $this->Session->read('paginate_conditions_type');
			$category = $this->Session->read('paginate_conditions_category');
			$this->set('keywordSearch', $keyword);
			$this->set('keywordSearch2', $keyword2);
			$this->set('orgSearch', $org);
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

	// Use the rest interface to search for attributes. Usage:
	// MISP-base-url/attributes/restSearch/[api-key]/[value]/[type]/[category]/[orgc]
	// value, type, category, orgc are optional
	// the last 4 fields accept the following operators:
	// && - you can use && between two search values to put a logical OR between them. for value, 1.1.1.1&&2.2.2.2 would find attributes with the value being either of the two.
	// ! - you can negate a search term. For example: google.com&&!mail would search for all attributes with value google.com but not ones that include mail. www.google.com would get returned, mail.google.com wouldn't.
	public function restSearch($key='download', $value=null, $type=null, $category=null, $org=null, $tags=null) {
		if ($tags) $tags = str_replace(';', ':', $tags);
		if ($value === 'null') $value = null;
		if ($type === 'null') $type = null;
		if ($category === 'null') $category = null;
		if ($org === 'null') $org = null;
		if ($key!=null && $key!='download') {
			$user = $this->checkAuthUser($key);
		} else {
			if (!$this->Auth->user()) throw new UnauthorizedException('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.');
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}
		if (!$user) {
			throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
		}
		$value = str_replace('|', '/', $value);
		if (!isset($this->request->params['ext']) || $this->request->params['ext'] !== 'json') {
			$this->response->type('xml');	// set the content type
			$this->layout = 'xml/default';
			$this->header('Content-Disposition: download; filename="misp.search.attribute.results.xml"');
		} else {
			$this->response->type('json');	// set the content type
			$this->layout = 'json/default';
			$this->header('Content-Disposition: download; filename="misp.search.attribute.results.json"');
		}
		$conditions['AND'] = array();
		$subcondition = array();
		$this->loadModel('Attribute');
		// add the values as specified in the 2nd parameter to the conditions
		$values = explode('&&', $value);
		$parameters = array('value', 'type', 'category', 'org');
		
		foreach ($parameters as $k => $param) {
			if (isset(${$parameters[$k]}) && ${$parameters[$k]}!=='null') {
				$elements = explode('&&', ${$parameters[$k]});
				foreach($elements as $v) {
					if (substr($v, 0, 1) == '!') {
						if ($parameters[$k] === 'value' && preg_match('@^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$@', substr($v, 1))) {
							$cidrresults = $this->Cidr->CIDR(substr($v, 1));
							foreach ($cidrresults as $result) {
								$subcondition['AND'][] = array('Attribute.value NOT LIKE' => $result);
							}
						} else {
							if ($parameters[$k] === 'org') {
								$subcondition['AND'][] = array('Event.' . $parameters[$k] . ' NOT LIKE' => '%'.substr($v, 1).'%');
							} else {
								$subcondition['AND'][] = array('Attribute.' . $parameters[$k] . ' NOT LIKE' => '%'.substr($v, 1).'%');
							}
						}
					} else {
						if ($parameters[$k] === 'value' && preg_match('@^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))$@', substr($v, 1))) {
							$cidrresults = $this->Cidr->CIDR($v);
							foreach ($cidrresults as $result) {
								$subcondition['OR'][] = array('Attribute.value LIKE' => $result);
							}
						} else {
							if ($parameters[$k] === 'org') {
								$subcondition['OR'][] = array('Event.' . $parameters[$k] . ' LIKE' => '%'.$v.'%');
							} else {
								$subcondition['OR'][] = array('Attribute.' . $parameters[$k] . ' LIKE' => '%'.$v.'%');
							}
						}
					}
				}
				array_push ($conditions['AND'], $subcondition);
				$subcondition = array();
			}
		}

		// If we are looking for an attribute, we want to retrieve some extra data about the event to be able to check for the permissions.

		if (!$user['User']['siteAdmin']) {
			$temp = array();
			$temp['AND'] = array('Event.distribution >' => 0, 'Attribute.distribution >' => 0);
			$subcondition['OR'][] = $temp;
			$subcondition['OR'][] = array('Event.org' => $user['User']['org']);
			array_push($conditions['AND'], $subcondition);
		}
		// If we sent any tags along, load the associated tag names for each attribute
		if ($tags) {
			$args = $this->Attribute->dissectArgs($tags);
			$this->loadModel('Tag');
			$tagArray = $this->Tag->fetchEventTagIds($args[0], $args[1]);
			$temp = array();
			foreach ($tagArray[0] as $accepted) {
				$temp['OR'][] = array('Event.id' => $accepted);
			}
			$conditions['AND'][] = $temp;
			$temp = array();
			foreach ($tagArray[1] as $rejected) {
				$temp['AND'][] = array('Event.id !=' => $rejected);
			}
			$conditions['AND'][] = $temp;
		}

		// change the fields here for the attribute export!!!! Don't forget to check for the permissions, since you are not going through fetchevent. Maybe create fetchattribute?
		
		$params = array(
				'conditions' => $conditions,
				'fields' => array('Attribute.*', 'Event.org', 'Event.distribution'),
				'contain' => array('Event' => array())
		);
		$results = $this->Attribute->find('all', $params);
		$this->loadModel('Whitelist');
		$results = $this->Whitelist->removeWhitelistedFromArray($results, true);
		if (empty($results)) throw new NotFoundException('No matches.');
		$this->set('results', $results);
	}

	// returns an XML with attributes that belong to an event. The type of attributes to be returned can be restricted by type using the 3rd parameter.
	// Similar to the restSearch, this parameter can be chained with '&&' and negations are accepted too. For example filename&&!filename|md5 would return all filenames that don't have an md5
	// The usage of returnAttributes is the following: [MISP-url]/attributes/returnAttributes/<API-key>/<type>/<signature flag>
	// The signature flag is off by default, enabling it will only return attribugtes that have the to_ids flag set to true.
	public function returnAttributes($key, $id, $type = null, $sigOnly = false) {
		$user = $this->checkAuthUser($key);
		// if the user is authorised to use the api key then user will be populated with the user's account
		// in addition we also set a flag indicating whether the user is a site admin or not.
		if (!$user) {
			throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
		}
		$this->loadModel('Event');
		$this->Event->read(null, $id);
		$myEventOrAdmin = false;
		if ($user['User']['siteAdmin'] || $this->Event->data['Event']['org'] == $user['User']['org']) {
			$myEventOrAdmin = true;
		}

		if (!$myEventOrAdmin) {
			if ($this->Event->data['Event']['distribution'] == 0) {
				throw new UnauthorizedException('You don\'t have access to that event.');
			}
		}
		$this->response->type('xml');	// set the content type
		$this->layout = 'xml/default';
		$this->header('Content-Disposition: download; filename="misp.search.attribute.results.xml"');
		// check if user can see the event!
		$conditions['AND'] = array();
		$include = array();
		$exclude = array();
		$attributes = array();
		// If there is a type set, create the include and exclude arrays from it
		if (isset($type)) {
			$elements = explode('&&', $type);
			foreach($elements as $v) {
				if (substr($v, 0, 1) == '!') {
					$exclude[] = substr($v, 1);
				} else {
					$include[] = $v;
				}
			}
		}

		// check each attribute
		foreach($this->Event->data['Attribute'] as $k => $attribute) {
			$contained = false;
			// If the include list is empty, then we just then the first check should always set contained to true (basically we chose type = all - exclusions, or simply all)
			if (empty($include)) {
				$contained = true;
			} else {
				// If we have elements in $include we should check if the attribute's type should be included
				foreach ($include as $inc) {
					if (strpos($attribute['type'], $inc) !== false) {
						$contained = true;
					}
				}
			}
			// If we have either everything included or the attribute passed the include check, we should check if there is a reason to exclude the attribute
			// For example, filename may be included, but md5 may be excluded, meaning that filename|md5 should be removed
			if ($contained) {
				foreach ($exclude as $exc) {
					if (strpos($attribute['type'], $exc) !== false) {
						$contained = false;
						continue 2;
					}
				}
			}
			// If we still didn't throw the attribute away, let's check if the user requesting the attributes is of the owning organisation of the event
			// and if not, whether the distribution of the attribute allows the user to see it
			if ($contained && !$myEventOrAdmin && $attribute['distribution'] == 0) {
				$contained = false;
			}

			// If we have set the sigOnly parameter and the attribute has to_ids set to false, discard it!
			if ($contained && $sigOnly === 'true' && !$attribute['to_ids']) {
				$contained = false;
			}

			// If after all of this $contained is still true, let's add the attribute to the array
			if ($contained) $attributes[] = $attribute;
		}
		if (empty($attributes)) throw new NotFoundException('No matches.');
		$this->set('results', $attributes);
	}

	public function downloadAttachment($key='download', $id) {
		if ($key!=null && $key!='download') {
			$user = $this->checkAuthUser($key);
		} else {
			if (!$this->Auth->user()) throw new UnauthorizedException('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.');
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}
		// if the user is authorised to use the api key then user will be populated with the user's account
		// in addition we also set a flag indicating whether the user is a site admin or not.
		if (!$user) {
			throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
		}
		$this->Attribute->id = $id;
		if(!$this->Attribute->exists()) {
			throw new NotFoundException('Invalid attribute or no authorisation to view it.');
		}
		$this->Attribute->read(null, $id);
		if (!$user['User']['siteAdmin'] &&
			$user['User']['org'] != $this->Attribute->data['Event']['org'] &&
			($this->Attribute->data['Event']['distribution'] == 0 ||
				$this->Attribute->data['Attribute']['distribution'] == 0
			)) {
			throw new NotFoundException('Invalid attribute or no authorisation to view it.');
		}
		$this->__downloadAttachment($this->Attribute->data['Attribute']);
	}

	public function text($key='download', $type="", $tags='') {
		if ($key != 'download') {
			// check if the key is valid -> search for users based on key
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
		} else {
			if (!$this->Auth->user('id')) {
				throw new UnauthorizedException('You have to be logged in to do that.');
			}
		}
		$this->response->type('txt');	// set the content type
		$this->header('Content-Disposition: download; filename="misp.' . $type . '.txt"');
		$this->layout = 'text/default';
		$attributes = $this->Attribute->text($this->_checkOrg(), $this->_isSiteAdmin(), $type, $tags);
		$this->loadModel('Whitelist');
		$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		$this->set('attributes', $attributes);
	}
	

	public function reportValidationIssuesAttributes() {
		// TODO improve performance of this function by eliminating the additional SQL query per attribute
		// search for validation problems in the attributes
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$this->set('result', $this->Attribute->reportValidationIssuesAttributes());
	}
	
	public function generateCorrelation() {
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$k = $this->Attribute->generateCorrelation();
		$this->Session->setFlash(__('All done. ' . $k . ' attributes processed.'));
		$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
	}
}
