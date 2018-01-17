<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

class AttributesController extends AppController {

	public $components = array('Security', 'RequestHandler', 'Cidr');

	public $paginate = array(
			'limit' => 60,
			'maxLimit' => 9999,
			'conditions' => array('AND' => array('Attribute.deleted' => 0)),
			'order' => 'Attribute.event_id DESC'
	);

	public $helpers = array('Js' => array('Jquery'));

	public function beforeFilter() {
		parent::beforeFilter();

		$this->Auth->allow('restSearch');
		$this->Auth->allow('returnAttributes');
		$this->Auth->allow('downloadAttachment');
		$this->Auth->allow('text');
		$this->Auth->allow('rpz');
		$this->Auth->allow('bro');

		// permit reuse of CSRF tokens on the search page.
		if ('search' == $this->request->params['action']) {
			$this->Security->csrfUseOnce = false;
		}
		if ($this->action == 'add_attachment') {
			$this->Security->disabledFields = array('values');
		}
		$this->Security->validatePost = true;

		// convert uuid to id if present in the url and overwrite id field
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
		if (!$this->_isSiteAdmin()) {
			$this->paginate = Set::merge($this->paginate, array('conditions' => $this->Attribute->buildConditions($this->Auth->user())));
		}
	}

	public function index() {
		$this->Attribute->recursive = -1;
		$this->paginate['contain'] = array(
			'Event' => array(
				'fields' =>  array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.info', 'Event.user_id')
			),
			'Object' => array(
				'fields' => array('Object.id', 'Object.distribution', 'Object.sharing_group_id')
			)
		);
		if (!$this->_isRest()) {
			$this->Attribute->contain(array('AttributeTag' => array('Tag')));
		}
		$this->set('isSearch', 0);
		$attributes = $this->paginate();
		$org_ids = array();
		foreach ($attributes as $k => $attribute) {
			if (empty($attribute['Event']['id'])) {
				unset($attribute[$k]);
				continue;
			}
			if ($attribute['Attribute']['type'] == 'attachment' && preg_match('/.*\.(jpg|png|jpeg|gif)$/i', $attribute['Attribute']['value'])) {
				$attributes[$k]['Attribute']['image'] = $this->Attribute->base64EncodeAttachment($attribute['Attribute']);
			}
			$org_ids[$attribute['Event']['org_id']] = false;
			$org_ids[$attribute['Event']['orgc_id']] = false;
		}
		$orgs = $this->Attribute->Event->Orgc->find('list', array(
				'conditions' => array('Orgc.id' => array_keys($org_ids)),
				'fields' => array('Orgc.id', 'Orgc.name')
		));
		$this->set('orgs', $orgs);
		$this->set('attributes', $attributes);
		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
	}

	public function add($eventId) {
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('You don\'t have permissions to create attributes');
		}
		$this->loadModel('Event');
		if (Validation::uuid($eventId)) {
			$temp = $this->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $eventId)));
			if (empty($temp)) throw new NotFoundException('Invalid event');
			$eventId = $temp['Event']['id'];
		} else if (!is_numeric($eventId)) {
			throw new NotFoundException(__('Invalid event'));
		}
		$this->Event->id = $eventId;
		if (!$this->Event->exists()) {
			throw new NotFoundException(__('Invalid event'));
		}
		// remove the published flag from the event
		$this->Event->recursive = -1;
		$this->Event->read(null, $eventId);
		if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
			throw new UnauthorizedException('You do not have permission to do that.');
		}
		if ($this->request->is('ajax'))	{
			$this->set('ajax', true);
			$this->layout = 'ajax';
		} else {
			$this->set('ajax', false);
		}
		if ($this->request->is('post')) {
			if ($this->request->is('ajax')) $this->autoRender = false;
			$date = new DateTime();
			if (!isset($this->request->data['Attribute'])) {
				$this->request->data = array('Attribute' => $this->request->data);
			}
			//
			// multiple attributes in batch import
			//
			$attributes = array();
			if (!empty($this->request->data['Attribute']['batch_import']) || (!empty($this->request->data['Attribute']['value']) && is_array($this->request->data['Attribute']['value']))) {
				$attributes = array();
				if (is_array($this->request->data['Attribute']['value'])) {
					$values = $this->request->data['Attribute']['value'];
				} else {
					$values = explode("\n", $this->request->data['Attribute']['value']);
				}
				foreach ($values as $value) {
					$this->request->data['Attribute']['value'] = $value;
					$attributes[] = $this->request->data['Attribute'];
				}
			} else {
				$attributes = $this->request->data['Attribute'];
			}
			if (!isset($attributes[0])) {
				$attributes = array(0 => $attributes);
			}
			$uuids = array();
			$this->Warninglist = ClassRegistry::init('Warninglist');
			$warnings = array();
			foreach ($attributes as $k => $attribute) {
				if (isset($attribute['id'])) {
					unset($attribute['id']);
				}
				$attributes[$k]['event_id'] = $eventId;
				if (isset($attribute['uuid'])) {
					$uuids[$k] = $attribute['uuid'];
					if (!isset($attribute['timestamp'])) {
						$attributes[$k]['timestamp'] = $date->getTimestamp();
					}
					if (isset($attribute['base64'])) {
						$attributes[$k]['data'] = $attribute['base64'];
					}
				}
				if (isset($attribute['type']) && !isset($attribute['category'])) {
					$attributes[$k]['category'] = $this->Attribute->typeDefinitions[$attribute['type']]['default_category'];
				}
				if (!isset($attribute['to_ids'])) {
					$attributes[$k]['to_ids'] = $this->Attribute->typeDefinitions[$attribute['type']]['to_ids'];
				}
				if (!empty($attributes[$k]['enforceWarninglist']) || !empty($this->params['named']['enforceWarninglist'])) {
					if (empty($warninglists)) $warninglists = $this->Warninglist->fetchForEventView();
					if (!$this->Warninglist->filterWarninglistAttributes($warninglists, $attributes[$k])) {
						$attributes[$k]['blocked'] = true;
					}
				}
			}
			$fails = array();
			$successes = 0;
			$attributeCount = count($attributes);
			if (!empty($uuids)) {
				$existingAttributes = $this->Attribute->find('list', array(
					'recursive' => -1,
					'fields' => array('Attribute.uuid'),
					'conditions' => array('Attribute.uuid' => array_values($uuids))
				));
				if (!empty($existingAttributes)) {
					foreach ($uuids as $k => $uuid) {
						if (in_array($uuid, $existingAttributes)) {
							unset($attributes[$k]);
							$fails["attribute_$k"] = array('uuid' => array('An attribute with this uuid already exists.'));
							unset($uuids[$k]);
						}
					}
				}
			}
			// deduplication
			$duplicates = 0;
			foreach ($attributes as $k => $attribute) {
				foreach ($attributes as $k2 => $attribute2) {
					if ($k == $k2) continue;
					if (
						(
							!empty($attribute['uuid']) &&
							!empty($attribute2['uuid']) &&
							$attribute['uuid'] == $attribute2['uuid']
						) || (
							$attribute['value'] == $attribute2['value'] &&
							$attribute['type'] == $attribute2['type'] &&
							$attribute['category'] == $attribute2['category']
						)
					) {
						$duplicates++;
						unset($attributes[$k]);
						break;
					}
				}
			}
			foreach ($attributes as $k => $attribute) {
				if (empty($attribute['blocked'])) {
					$this->Attribute->set($attribute);
					$result = $this->Attribute->validates();
					if (!$result) {
						$fails["attribute_$k"] = $this->Attribute->validationErrors;
						unset($attributes[$k]);
					} else {
						$successes++;
					}
				} else {
					$fails["attribute_$k"] = 'Attribute blocked due to warninglist';
					unset($attributes[$k]);
				}
			}
			if (!empty($successes)) {
				$this->Event->unpublishEvent($eventId);
			}
			$result = $this->Attribute->saveMany($attributes);
			if ($this->_isRest()) {
				if (!empty($successes)) {
					$attributes = $this->Attribute->find('all', array(
						'recursive' => -1,
						'conditions' => array('Attribute.id' => $this->Attribute->inserted_ids)
					));
					if (count($attributes) == 1) {
						$attributes = $attributes[0];
					}
					return $this->RestResponse->viewData($attributes, $this->response->type(), $fails);
				} else {
					if ($attributeCount == 1) {
						return $this->RestResponse->saveFailResponse('Attributes', 'add', false, $fails["attribute_0"], $this->response->type());
					} else {
						return $this->RestResponse->saveFailResponse('Attributes', 'add', false, $fails, $this->response->type());
					}
				}
			} else {
				$message = '';
				$redirect = '/events/view/' . $eventId;
				if (empty($fails)) {
					$message = 'Attributes saved.';
				} else {
					if (count($attributes) > 1) {
						$failKeys = array_keys($fails);
						foreach ($failKeys as $k => $v) {
							$v = explode('_', $v);
							$failKeys[$k] = intval($v[1]) + 1;
						}
						$message = 'Attributes saved, however, attributes ' . implode(', ', $failKeys) . ' could not be saved.';
					} else {
						if (!empty($fails["attribute_0"])) {
							foreach ($fails["attribute_0"] as $k => $v) {
								$message = 'Attribute validation failed [' . $k . ']: ' . $v[0];
								break;
							}
						} else {
							$message = 'Attribute could not be saved.';
						}
					}
				}
				if ($this->request->is('ajax')) {
					$this->autoRender = false;
					$errors = ($attributeCount > 1) ? $message : $this->Attribute->validationErrors;
					if (!empty($successes)) {
						return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message)),'status' => 200, 'type' => 'json'));
					} else {
						return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $errors)),'status' => 200, 'type' => 'json'));
					}
				} else {
					$this->Session->setFlash($message);
					if (count($successes) > 0) {
						$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
					}
				}
			}
		}
		// combobox for types
		$types = array_keys($this->Attribute->typeDefinitions);
		foreach ($types as $key => $value) {
			if (in_array($value, array('malware-sample', 'attachment'))) {
				unset($types[$key]);
			}
		}
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobox for categories
		$categories = array_keys($this->Attribute->categoryDefinitions);
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories', compact('categories'));
		$this->loadModel('Event');
		$events = $this->Event->findById($eventId);
		$this->set('event_id', $events['Event']['id']);
		// combobox for distribution
		$this->set('currentDist', $events['Event']['distribution']);
		// tooltip for distribution

		$this->loadModel('SharingGroup');
		$sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name',  1);
		$this->set('sharingGroups', $sgs);
		$info = array();
		$distributionLevels = $this->Attribute->distributionLevels;
		if (empty($sgs)) unset($distributionLevels[4]);
		$this->set('distributionLevels', $distributionLevels);
		foreach ($this->Attribute->categoryDefinitions as $key => $value) {
			$info['category'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($this->Attribute->typeDefinitions as $key => $value) {
			$info['type'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($distributionLevels as $key => $value) {
			$info['distribution'][$key] = array('key' => $value, 'desc' => $this->Attribute->distributionDescriptions[$key]['formdesc']);
		}
		$this->set('info', $info);
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
			$this->Auth->user('org_id') !=
			$this->Attribute->data['Event']['org_id'] &&
			($this->Attribute->data['Event']['distribution'] == 0 ||
				$this->Attribute->data['Attribute']['distribution'] == 0
			)) {
			throw new UnauthorizedException('You do not have the permission to view this event.');
		}
		$this->__downloadAttachment($this->Attribute->data['Attribute']);
	}

	private function __downloadAttachment($attribute) {
		$attachments_dir = Configure::read('MISP.attachments_dir');
		if (empty($attachments_dir)) {
			$this->loadModel('Server');
			$attachments_dir = $this->Server->getDefaultAttachments_dir();
		}
		$path = $attachments_dir . DS . $attribute['event_id'] . DS;
		$file = $attribute['id'];
		if ('attachment' == $attribute['type']) {
			$filename = $attribute['value'];
			$fileExt = pathinfo($filename, PATHINFO_EXTENSION);
			$filename = substr($filename, 0, strlen($filename) - strlen($fileExt) - 1);
		} else if ('malware-sample' == $attribute['type']) {
			$filenameHash = explode('|', $attribute['value']);
			$filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
			$fileExt = "zip";
		} else {
			throw new NotFoundException(__('Attribute not an attachment or malware-sample'));
		}
		$this->autoRender = false;
		$this->response->type($fileExt);
		$this->response->file($path . $file, array('download' => true, 'name' => $filename . '.' . $fileExt));
	}

	public function add_attachment($eventId = null) {
		if ($this->request->is('post')) {
			$hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
			$this->loadModel('Event');
			$this->Event->id = $this->request->data['Attribute']['event_id'];
			$this->Event->recursive = -1;
			$this->Event->read();
			if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
				throw new UnauthorizedException('You do not have permission to do that.');
			}
			$partialFails = array();
			$fails = array();
			$success = 0;

			foreach ($this->request->data['Attribute']['values'] as $k => $value) {
				// Check if there were problems with the file upload
				// only keep the last part of the filename, this should prevent directory attacks
				$filename = basename($value['name']);
				$tmpfile = new File($value['tmp_name']);
				if ((isset($value['error']) && $value['error'] == 0) ||
					(!empty($value['tmp_name']) && $value['tmp_name'] != 'none')
				) {
					if (!is_uploaded_file($tmpfile->path))
						throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
				} else {
					$fails[] = $filename;
					continue;
				}

				if ($this->request->data['Attribute']['malware']) {
					if ($this->request->data['Attribute']['advanced']) {
						$result = $this->Attribute->advancedAddMalwareSample(
							$eventId,
							$this->request->data['Attribute'],
							$filename,
							$tmpfile
						);
						if ($result) $success++;
						else $fails[] = $filename;
					} else {
						$result = $this->Attribute->simpleAddMalwareSample(
							$eventId,
							$this->request->data['Attribute'],
							$filename,
							$tmpfile
						);
						if ($result) $success++;
						else $fails[] = $filename;
					}
					if (!empty($result)) {
						foreach ($result['Object'] as $object) {
							$this->loadModel('MispObject');
							$this->MispObject->captureObject(array('Object' => $object), $eventId, $this->Auth->user());
						}
						if (!empty($result['ObjectReference'])) {
							foreach ($result['ObjectReference'] as $reference) {
								$this->MispObject->ObjectReference->smartSave($reference, $eventId);
							}
						}
					}
				} else {
					$attribute = array(
							'Attribute' => array(
								'value' => $filename,
								'category' => $this->request->data['Attribute']['category'],
								'type' => 'attachment',
								'event_id' => $this->request->data['Attribute']['event_id'],
								'data' => base64_encode($tmpfile->read()),
								'comment' => $this->request->data['Attribute']['comment'],
								'to_ids' => 0,
								'distribution' => $this->request->data['Attribute']['distribution'],
								'sharing_group_id' => isset($this->request->data['Attribute']['sharing_group_id']) ? $this->request->data['Attribute']['sharing_group_id'] : 0,
							)
					);
					$this->Attribute->create();
					$r = $this->Attribute->save($attribute);
					if ($r == false) $fails[] = $filename;
					else $success++;
				}
			}
			$message = 'The attachment(s) have been uploaded.';
			if (!empty($partialFails)) $message .= ' Some of the attributes however could not be created.';
			if (!empty($fails)) $message = 'Some of the attachments failed to upload. The failed files were: ' . implode(', ', $fails) . ' - This can be caused by the attachments already existing in the event.';
			if (empty($success)) {
				if (empty($fails)) $message = 'The attachment(s) could not be saved. please contact your administrator.';
			} else {
				$this->Event->id = $this->request->data['Attribute']['event_id'];
				$this->Event->saveField('published', 0);
			}
			$this->Session->setFlash($message);
			$this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
		} else {
			// set the event_id in the form
			$this->request->data['Attribute']['event_id'] = $eventId;
		}

		// combobox for categories
		$categories = array_keys($this->Attribute->categoryDefinitions);
		// just get them with attachments..
		$selectedCategories = array();
		foreach ($categories as $category) {
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
		$categories = $this->_arrayToValuesIndexArray($selectedCategories);
		$this->set('categories',$categories);

		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);

		$this->set('zippedDefinitions', $this->Attribute->zippedDefinitions);
		$this->set('uploadDefinitions', $this->Attribute->uploadDefinitions);

		// combobox for distribution
		$this->loadModel('Event');
		$this->set('distributionLevels', $this->Event->Attribute->distributionLevels);

		foreach ($this->Attribute->categoryDefinitions as $key => $value) {
			$info['category'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($this->Event->Attribute->distributionLevels as $key => $value) {
			$info['distribution'][$key] = array('key' => $value, 'desc' => $this->Attribute->distributionDescriptions[$key]['formdesc']);
		}
		$this->set('info', $info);

		$this->loadModel('SharingGroup');
		$sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
		$this->set('sharingGroups', $sgs);

		$events = $this->Event->findById($eventId);
		$this->set('currentDist', $events['Event']['distribution']);
		$this->set('published', $events['Event']['published']);
	}


	// Imports the CSV threatConnect file to multiple attributes
	public function add_threatconnect($eventId = null) {
		if ($this->request->is('post')) {

			$this->loadModel('Event');
			$this->Event->id = $eventId;
			$this->Event->recursive = -1;
			$this->Event->read();
			if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
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
			if (($handle = fopen($filename, 'r')) !== false) {
				while (($row = fgetcsv($handle, 0, ',', '"')) !== false) {
					if (!$header)
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
			foreach ($entries as $entry) {
				$attribute = array();
				$attribute['event_id'] = $this->request->data['Attribute']['event_id'];
				$attribute['value'] = $entry['Value'];
				$attribute['to_ids'] = ($entry['Confidence'] > 51) ? 1 : 0; // To IDS if high confidence
				$attribute['comment'] = $entry['Description'];
				$attribute['distribution'] = '3'; // 'All communities'
				if (Configure::read('MISP.default_attribute_distribution') != null) {
					if (Configure::read('MISP.default_attribute_distribution') === 'event') {
						$attribute['distribution'] = $this->Event->data['Event']['distribution'];
					} else {
						$attribute['distribution'] = Configure::read('MISP.default_attribute_distribution');
					}
				}
				switch ($entry['Type']) {
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
			foreach ($entries as $entry) {
				if (empty($entry['Source'])) continue;
				$references[$entry['Source']] = true;
			}
			$references = array_keys($references);
			// generate the Attributes
			foreach ($references as $reference) {
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

			$results = array('successes' => 0, 'fails' => 0);
			foreach ($attributes as $attribute) {
				$this->Attribute->create();
				$result = $this->Attribute->save($attribute);
				if (!$result) {
					$results['fails']++;
				} else {
					$results['successes']++;
				}
			}
			// data imported (with or without errors)
			// remove the published flag from the event
			$this->loadModel('Event');
			$this->Event->id = $this->request->data['Attribute']['event_id'];
			$this->Event->saveField('published', 0);

			// everything is done, now redirect to event view
			$message = 'The ThreatConnect data has been imported.';
			if ($results['successes'] != 0) {
				$message .= ' ' . $results['successes'] . ' entries imported.';
			}
			if ($results['fails'] != 0) {
				$message .= ' ' . $results['fails'] . ' entries could not be imported.';
			}
			$this->Session->setFlash(__($message));
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


	public function edit($id = null) {
		if (Validation::uuid($id)) {
			$this->Attribute->recursive = -1;
			$temp = $this->Attribute->findByUuid($id);
			if ($temp == null) throw new NotFoundException('Invalid attribute');
			$id = $temp['Attribute']['id'];
		} else if (!is_numeric($id)) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$this->Attribute->id = $id;
		$date = new DateTime();
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$this->Attribute->read();
		if ($this->Attribute->data['Attribute']['deleted']) throw new NotFoundException(__('Invalid attribute'));
		if (!$this->_isSiteAdmin()) {
			if ($this->Attribute->data['Event']['orgc_id'] == $this->Auth->user('org_id')
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
		} else {
			$this->set('attachment', false);
		}
		if ($this->request->is('post') || $this->request->is('put')) {
			if (!isset($this->request->data['Attribute'])) {
				$this->request->data = array('Attribute' => $this->request->data);
			}
			$existingAttribute = $this->Attribute->findByUuid($this->Attribute->data['Attribute']['uuid']);
			// check if the attribute has a timestamp already set (from a previous instance that is trying to edit via synchronisation)
			// check which attribute is newer
			if (count($existingAttribute) && !$existingAttribute['Attribute']['deleted']) {
				$this->request->data['Attribute']['id'] = $existingAttribute['Attribute']['id'];
				$dateObj = new DateTime();
				if (!isset($this->request->data['Attribute']['timestamp'])) $this->request->data['Attribute']['timestamp'] = $dateObj->getTimestamp();
				if ($this->request->data['Attribute']['timestamp'] > $existingAttribute['Attribute']['timestamp']) {
					$recoverFields = array('value', 'to_ids', 'distribution', 'category', 'type', 'comment');
					foreach ($recoverFields as $rF) {
						if (!isset($this->request->data['Attribute'][$rF])) $this->request->data['Attribute'][$rF] = $existingAttribute['Attribute'][$rF];
					}
					// carry on with adding this attribute - Don't forget! if orgc!=user org, create shadow attribute, not attribute!
				} else {
					// the old one is newer or the same, replace the request's attribute with the old one
					throw new MethodNotAllowedException('Attribute could not be saved: Attribute in the request not newer than the local copy.');
				}
			} else {
				if ($this->_isRest() || $this->response->type() === 'application/json') {
					throw new NotFoundException('Invalid attribute.');
				} else {
					$this->Session->setFlash(__('Invalid attribute.'));
					$this->redirect(array('controller' => 'events', 'action' => 'index'));
				}
			}
			$this->loadModel('Event');
			$event = $this->Attribute->Event->find('first', array(
				'recursive' => -1,
				'conditions' => array('Event.id' => $eventId)
			));
			if (empty($event)) {
				throw new NotFoundException('Invalid Event.');
			}
			if ($existingAttribute['Attribute']['object_id']) {
				$result = $this->Attribute->save($this->request->data, array('Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.comment', 'Attribute.distribution', 'Attribute.sharing_group_id'));
				$this->Attribute->Object->updateTimestamp($existingAttribute['Attribute']['object_id']);
			} else {
				$result = $this->Attribute->save($this->request->data);
			}
			if ($result) {
				$this->Session->setFlash(__('The attribute has been saved'));
				// remove the published flag from the event
				$this->Event->unpublishEvent($eventId);
				if (!empty($this->Attribute->data['Attribute']['object_id'])) {
					$object = $this->Attribute->Object->find('first', array(
						'recursive' => -1,
						'conditions' => array('Object.id' => $this->Attribute->data['Attribute']['object_id'])
					));
					if (!empty($object)) {
						$object['Object']['timestamp'] = $date->getTimestamp();
						$this->Attribute->Object->save($object);
					}
				}
				if ($this->_isRest() || $this->response->type() === 'application/json') {
					$saved_attribute = $this->Attribute->find('first', array(
							'conditions' => array('id' => $this->Attribute->id),
							'recursive' => -1,
							'fields' => array('id', 'type', 'to_ids', 'category', 'uuid', 'event_id', 'distribution', 'timestamp', 'comment', 'value', 'disable_correlation'),
					));
					$response = array('response' => array('Attribute' => $saved_attribute['Attribute']));
					$this->set('response', $response);
					if ($this->response->type() === 'application/json') $this->render('/Attributes/json/view');
					else $this->render('view');
					return;
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
		if (!empty($this->request->data['Attribute']['object_id'])) {
			$this->set('objectAttribute', true);
		} else {
			$this->set('objectAttribute', false);
		}
		// enabling / disabling the distribution field in the edit view based on whether user's org == orgc in the event
		$this->loadModel('Event');
		$this->Event->id = $eventId;
		$this->Event->read();
		$this->set('published', $this->Event->data['Event']['published']);
		// needed for RBAC
		// combobox for types
		$types = array_keys($this->Attribute->typeDefinitions);
		foreach ($types as $key => $value) {
			if (in_array($value, array('malware-sample', 'attachment'))) {
				unset($types[$key]);
			}
		}
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types', $types);
		// combobox for categories
		$this->set('currentDist', $this->Event->data['Event']['distribution']);

		$this->loadModel('SharingGroup');
		$sgs = $this->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name',  1);
		$this->set('sharingGroups', $sgs);

		$distributionLevels = $this->Attribute->distributionLevels;
		if (empty($sgs)) unset($distributionLevels[4]);
		$this->set('distributionLevels', $distributionLevels);

		foreach ($this->Attribute->categoryDefinitions as $key => $value) {
			$info['category'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($this->Attribute->typeDefinitions as $key => $value) {
			$info['type'][$key] = array('key' => $key, 'desc' => isset($value['formdesc'])? $value['formdesc'] : $value['desc']);
		}
		foreach ($distributionLevels as $key => $value) {
			$info['distribution'][$key] = array('key' => $value, 'desc' => $this->Attribute->distributionDescriptions[$key]['formdesc']);
		}
		$this->set('info', $info);
		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$categoryDefinitions = $this->Attribute->categoryDefinitions;
		$categories = array_keys($this->Attribute->categoryDefinitions);
		$categories = $this->_arrayToValuesIndexArray($categories);
		if (!empty($this->request->data['Attribute']['object_id'])) {
			foreach ($categoryDefinitions as $k => $v) {
				if (!in_array($this->request->data['Attribute']['type'], $v['types'])) {
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
		$this->set('categoryDefinitions', $categoryDefinitions);
	}

	// ajax edit - post a single edited field and this method will attempt to save it and return a json with the validation errors if they occur.
	public function editField($id) {
		if (Validation::uuid($id)) {
			$this->Attribute->recursive = -1;
			$temp = $this->Attribute->findByUuid($id);
			if ($temp == null) throw new NotFoundException('Invalid attribute');
			$id = $temp['Attribute']['id'];
		} else if (!is_numeric($id)) {
			throw new NotFoundException(__('Invalid event id.'));
		}
		if ((!$this->request->is('post') && !$this->request->is('put'))) throw new MethodNotAllowedException();
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			return new CakeResponse(array('body'=> json_encode(array('fail' => false, 'errors' => 'Invalid attribute')), 'status'=>200, 'type' => 'json'));
		}
		$this->Attribute->recursive = -1;
		$this->Attribute->contain('Event');
		$attribute = $this->Attribute->read();

		if (!$this->_isSiteAdmin()) {
			if ($this->Attribute->data['Event']['orgc_id'] == $this->Auth->user('org_id')
			&& (($this->userRole['perm_modify'] && $this->Attribute->data['Event']['user_id'] != $this->Auth->user('id'))
			|| $this->userRole['perm_modify_org'])) {
				// Allow the edit
			} else {
				return new CakeResponse(array('body'=> json_encode(array('fail' => false, 'errors' => 'Invalid attribute')), 'status'=>200, 'type' => 'json'));
			}
		}
		$validFields = array('value', 'category', 'type', 'comment', 'to_ids', 'distribution');
		$changed = false;
		if (empty($this->request->data['Attribute'])) {
			$this->request->data = array('Attribute' => $this->request->data);
			if (empty($this->request->data['Attribute'])) {
				throw new MethodNotAllowedException('Invalid input.');
			}
		}
		foreach ($this->request->data['Attribute'] as $changedKey => $changedField) {
			if (!in_array($changedKey, $validFields)) {
				throw new MethodNotAllowedException('Invalid field.');
			}
			if ($attribute['Attribute'][$changedKey] == $changedField) {
				$this->autoRender = false;
				return new CakeResponse(array('body'=> json_encode(array('errors'=> array('value' => 'nochange'))), 'status'=>200, 'type' => 'json'));
			}
			$attribute['Attribute'][$changedKey] = $changedField;
			$changed = true;
		}
		if (!$changed) {
			return new CakeResponse(array('body'=> json_encode(array('errors'=> array('value' => 'nochange'))), 'status'=>200, 'type' => 'json'));
		}
		$date = new DateTime();
		$attribute['Attribute']['timestamp'] = $date->getTimestamp();
		if ($this->Attribute->save($attribute)) {
			$event = $this->Attribute->Event->find('first', array(
				'recursive' => -1,
				'fields' => array('id', 'published', 'timestamp', 'info', 'uuid'),
				'conditions' => array(
					'id' => $attribute['Attribute']['event_id'],
			)));
			$event['Event']['timestamp'] = $date->getTimestamp();
			$event['Event']['published'] = 0;
			$this->Attribute->Event->save($event, array('fieldList' => array('published', 'timestamp', 'info')));
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Field updated.', 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
		} else {
			$this->autoRender = false;
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $this->Attribute->validationErrors)), 'status'=>200, 'type' => 'json'));
		}
	}

	public function view($id) {
		if (Validation::uuid($id)) {
			$temp = $this->Attribute->find('first', array(
				'recursive' => -1,
				'conditions' => array('Attribute.uuid' => $id),
				'fields' => array('Attribute.id', 'Attribute.uuid')
			));
			if (empty($temp)) throw new NotFoundException('Invalid attribute');
			$id = $temp['Attribute']['id'];
		} else if (!is_numeric($id)) {
			throw new NotFoundException(__('Invalid attribute id.'));
		}
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException('Invalid attribute');
		}
		if ($this->_isRest()) {
			$conditions = array('conditions' => array('Attribute.id' => $id), 'withAttachments' => true);
			$conditions['includeAllTags'] = false;
			$conditions['includeAttributeUuid'] = true;
			$attribute = $this->Attribute->fetchAttributes($this->Auth->user(), $conditions);
			if (empty($attribute)) throw new MethodNotAllowedException('Invalid attribute');
			$attribute = $attribute[0];
			if (isset($attribute['AttributeTag'])) {
				foreach ($attribute['AttributeTag'] as $k => $tag) {
					$attribute['Attribute']['Tag'][$k] = $tag['Tag'];
				}
			}
			unset($attribute['Attribute']['value1']);
			unset($attribute['Attribute']['value2']);
			$this->set('Attribute', $attribute['Attribute']);
			$this->set('_serialize', array('Attribute'));
		} else {
			$this->redirect('/events/view/' . $this->Attribute->data['Attribute']['event_id']);
		}
	}

	public function delete($id, $hard = false) {
		if (Validation::uuid($id)) {
			$this->Attribute->recursive = -1;
			$temp = $this->Attribute->findByUuid($id);
			if ($temp == null) throw new NotFoundException('Invalid attribute');
			$id = $temp['Attribute']['id'];
		} else if (!is_numeric($id)) {
			throw new NotFoundException('Invalid attribute');
		}
		$this->set('id', $id);
		$conditions = array('id' => $id);
		if (!$hard) $conditions['deleted'] = 0;
		$attribute = $this->Attribute->find('first', array(
				'conditions' => $conditions,
				'recursive' => -1,
				'fields' => array('id', 'event_id'),
		));
		if (empty($attribute)) throw new NotFoundException('Invalid Attribute');
		if ($this->request->is('ajax')) {
			if ($this->request->is('post')) {
				if ($this->__delete($id, $hard)) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Attribute deleted.')), 'status'=>200, 'type' => 'json'));
				} else {
					return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Attribute was not deleted.')), 'status'=>200, 'type' => 'json'));
				}
			} else {
				$this->set('hard', $hard);
				$this->set('event_id', $attribute['Attribute']['event_id']);
				$this->render('ajax/attributeConfirmationForm');
			}
		} else {
			if (!$this->request->is('post') && !$this->_isRest()) {
				throw new MethodNotAllowedException();
			}
			if ($this->__delete($id, $hard)) {
				if ($this->_isRest() || $this->response->type() === 'application/json') {
					$this->set('message', 'Attribute deleted.');
					$this->set('_serialize', array('message'));
				} else {
					$this->Session->setFlash(__('Attribute deleted'));
					$this->redirect($this->referer());
				}
			} else {
				if ($this->_isRest() || $this->response->type() === 'application/json') {
					throw new Exception('Attribute was not deleted');
				} else {
					$this->Session->setFlash(__('Attribute was not deleted'));
					$this->redirect(array('action' => 'index'));
				}
				$this->Session->setFlash(__('Attribute deleted'));
			}
		}
	}


	public function restore($id = null) {
		$attribute = $this->Attribute->find('first', array(
				'conditions' => array('Attribute.id' => $id),
				'recursive' => -1,
				'fields' => array('Attribute.id', 'Attribute.event_id'),
				'contain' => array(
					'Event' => array(
						'fields' => array('Event.orgc_id')
					)
				)
		));
		if (empty($attribute) || !$this->userRole['perm_site_admin'] && $this->Auth->user('org_id') != $attribute['Event']['orgc_id']) {
			if ($this->request->is('ajax')) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Attribute')), 'type' => 'json', 'status'=>200));
			else throw new MethodNotAllowedException('Invalid Attribute');
		}
		if ($this->request->is('ajax')) {
			if ($this->request->is('post')) {
				$result = $this->Attribute->restore($id, $this->Auth->user());
				if ($result === true) return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Attribute restored.')), 'type' => 'json' ,'status'=>200));
				else return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $result)), 'type' => 'json', 'status'=>200));
			} else {
				$this->set('id', $id);
				$this->set('event_id', $attribute['Attribute']['event_id']);
				$this->render('ajax/attributeRestorationForm');
			}
		} else {
			if (!$this->request->is('post') && !$this->_isRest()) throw new MethodNotAllowedException();
			if ($this->Attribute->restore($id, $this->Auth->user())) {
				$this->Attribute->__alterAttributeCount($this->data['Attribute']['event_id']);
				$this->redirect(array('action' => 'view', $id));
			}	else throw new NotFoundException('Could not restore the attribute');
		}
	}


	// unification of the actual delete for the multi-select
	private function __delete($id, $hard = false) {
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			return false;
		}
		$result = $this->Attribute->find('first', array(
			'conditions' => array('Attribute.id' => $id),
			'fields' => array('Attribute.*'),
			'contain' => array('Event' => array(
				'fields' => array('Event.*')
			)),
		));
		if (empty($result)) throw new MethodNotAllowedException('Attribute not found or not authorised.');

		// check for permissions
		if (!$this->_isSiteAdmin()) {
			if ($result['Event']['locked']) {
				if ($this->Auth->user('org_id') != $result['Event']['org_id'] || !$this->userRole['perm_sync']) {
					throw new MethodNotAllowedException('Attribute not found or not authorised.');
				}
			} else {
				if ($this->Auth->user('org_id') != $result['Event']['orgc_id']) {
					throw new MethodNotAllowedException('Attribute not found or not authorised.');
				}
			}
		}
		$date = new DateTime();
		if ($hard) {
			$save = $this->Attribute->delete($id);
		} else {
			if (Configure::read('Security.sanitise_attribute_on_delete')) {
					$result['Attribute']['category'] = 'Other';
					$result['Attribute']['type'] = 'comment';
					$result['Attribute']['value'] = 'deleted';
					$result['Attribute']['comment'] = '';
					$result['Attribute']['to_ids'] = 0;
			}
			$result['Attribute']['deleted'] = 1;
			$result['Attribute']['timestamp'] = $date->getTimestamp();
			$save = $this->Attribute->save($result);
			$object_refs = $this->Attribute->Object->ObjectReference->find('all', array(
				'conditions' => array(
					'ObjectReference.referenced_type' => 0,
					'ObjectReference.referenced_id' => $id,
				),
				'recursive' => -1
			));
			foreach ($object_refs as $ref) {
				$ref['ObjectReference']['deleted'] = 1;
				$this->Attribute->Object->ObjectReference->save($ref);
			}
		}
		// attachment will be deleted with the beforeDelete() function in the Model
		if ($save) {
			// We have just deleted the attribute, let's also check if there are any shadow attributes that were attached to it and delete them
			$this->loadModel('ShadowAttribute');
			$this->ShadowAttribute->deleteAll(array('ShadowAttribute.old_id' => $id), false);

			// remove the published flag from the event
			$this->Attribute->Event->unpublishEvent($result['Event']['id']);
			return true;
		} else {
			return false;
		}
	}

	public function deleteSelected($id) {
		if (!$this->request->is('post') || !$this->request->is('ajax')) {
			throw new MethodNotAllowedException();
		}
		// get a json object with a list of attribute IDs to be deleted
		// check each of them and return a json object with the successful deletes and the failed ones.
		$ids = json_decode($this->request->data['Attribute']['ids_delete']);

		if (!$this->_isSiteAdmin()) {
			$event = $this->Attribute->Event->find('first', array(
					'conditions' => array('id' => $id),
					'recursive' => -1,
					'fields' => array('id', 'orgc_id', 'user_id')
			));
			if ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || (!$this->userRole['perm_modify_org'] && !($this->userRole['perm_modify'] && $event['Event']['user_id'] == $this->Auth->user('id')))) {
				throw new MethodNotAllowedException('Invalid Event.');
			}
		}
		// find all attributes from the ID list that also match the provided event ID.
		$attributes = $this->Attribute->find('all', array(
			'recursive' => -1,
			'conditions' => array('id' => $ids, 'event_id' => $id),
			'fields' => array('id', 'event_id')
		));
		$successes = array();
		foreach ($attributes as $a) {
			if ($this->__delete($a['Attribute']['id'])) $successes[] = $a['Attribute']['id'];
		}
		$fails = array_diff($ids, $successes);
		$this->autoRender = false;
		if (count($fails) == 0 && count($successes) > 0) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => count($successes) . ' attribute' . (count($successes) != 1 ? 's' : '') . ' deleted.')), 'status'=>200, 'type' => 'json'));
		} else {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => count($successes) . ' attribute' . (count($successes) != 1 ? 's' : '') . ' deleted, but ' . count($fails) . ' attribute' . (count($fails) != 1 ? 's' : '') . ' could not be deleted.')), 'status'=>200, 'type' => 'json'));
		}
	}

	public function editSelected($id) {
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This method can only be accessed via AJAX.');

		if ($this->request->is('post')) {
			$event = $this->Attribute->Event->find('first', array(
				'conditions' => array('id' => $id),
				'recursive' => -1,
				'fields' => array('id', 'orgc_id', 'user_id', 'published', 'timestamp', 'info', 'uuid')
			));
			if (!$this->_isSiteAdmin()) {
				if ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || (!$this->userRole['perm_modify_org'] && !($this->userRole['perm_modify'] && $event['user_id'] == $this->Auth->user('id')))) {
					throw new MethodNotAllowedException('You are not authorized to edit this event.');
				}
			}
			$attribute_ids = json_decode($this->request->data['Attribute']['attribute_ids']);
			$attributes = $this->Attribute->find('all', array(
				'conditions' => array(
					'id' => $attribute_ids,
					'event_id' => $id,
				),
				'recursive' => -1,
			));

			if ($this->request->data['Attribute']['to_ids'] == 2 && $this->request->data['Attribute']['distribution'] == 6 && $this->request->data['Attribute']['comment'] == null) {
				$this->autoRender = false;
				return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200, 'type' => 'json'));
			}

			if ($this->request->data['Attribute']['to_ids'] != 2) {
				foreach ($attributes as $key => $attribute) {
					$attributes[$key]['Attribute']['to_ids'] = ($this->request->data['Attribute']['to_ids'] == 0 ? false : true);
				}
			}

			if ($this->request->data['Attribute']['distribution'] != 6) {
				foreach ($attributes as $key => $attribute) {
					$attributes[$key]['Attribute']['distribution'] = $this->request->data['Attribute']['distribution'];
				}
				if ($this->request->data['Attribute']['distribution'] == 4) {
					foreach ($attributes as $key => $attribute) {
						$attributes[$key]['Attribute']['sharing_group_id'] = $this->request->data['Attribute']['sharing_group_id'];
					}
				} else {
					foreach ($attributes as $key => $attribute) {
						$attributes[$key]['Attribute']['sharing_group_id'] = 0;
					}
				}
			}

			if ($this->request->data['Attribute']['comment'] != null) {
				foreach ($attributes as $key => $attribute) {
					$attributes[$key]['Attribute']['comment'] = $this->request->data['Attribute']['comment'];
				}
			}

			$date = new DateTime();
			$timestamp = $date->getTimestamp();
			foreach ($attributes as $key => $attribute) {
				$attributes[$key]['Attribute']['timestamp'] = $timestamp;
			}

			if ($this->Attribute->saveMany($attributes)) {
				$event['Event']['timestamp'] = $date->getTimestamp();
				$event['Event']['published'] = 0;
				$this->Attribute->Event->save($event, array('fieldList' => array('published', 'timestamp', 'info', 'id')));
				$this->autoRender = false;
				return new CakeResponse(array('body'=> json_encode(array('saved' => true)), 'status' => 200, 'type' => 'json'));
			} else {
				$this->autoRender = false;
				return new CakeResponse(array('body'=> json_encode(array('saved' => false)), 'status' => 200, 'type' => 'json'));
			}
		} else {
			if (!isset($id)) throw new MethodNotAllowedException('No event ID provided.');
			$this->layout = 'ajax';
			$this->set('id', $id);
			$this->set('sgs', $this->Attribute->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', true));
			$this->set('distributionLevels', $this->Attribute->distributionLevels);
			$this->set('distributionDescriptions', $this->Attribute->distributionDescriptions);
			$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
			$this->render('ajax/attributeEditMassForm');
		}
	}

	// Deletes this specific attribute from all remote servers
	private function __deleteAttributeFromServers($uuid) {
		// get a list of the servers with push active
		$this->loadModel('Server');
		$servers = $this->Server->find('all', array('conditions' => array('push' => 1)));

		// iterate over the servers and upload the attribute
		if (empty($servers))
			return;
		App::uses('SyncTool', 'Tools');
		foreach ($servers as $server) {
			$syncTool = new SyncTool();
			$HttpSocket = $syncTool->setupHttpSocket($server);
			$this->Attribute->deleteAttributeFromServer($uuid, $server, $HttpSocket);
		}
	}

	public function search() {
		$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
		$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
		$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);

		$fullAddress = '/attributes/search';
		// if no search is given, show the search form
		if ($this->request->here == $fullAddress && !$this->request->is('post')) {
			// adding filtering by category and type
			// combobox for types
			$types = array('' => array('ALL' => 'ALL'), 'types' => array());
			$types['types'] = array_merge($types['types'], $this->_arrayToValuesIndexArray(array_keys($this->Attribute->typeDefinitions)));
			ksort($types['types']);
			$this->set('types', $types);
			// combobox for categories
			$categories['categories'] = array_merge(array('ALL' => 'ALL'), $this->_arrayToValuesIndexArray(array_keys($this->Attribute->categoryDefinitions)));
			$this->set('categories', $categories);
		} else {
			$this->set('isSearch', 1);

			$attributeTagQuery = '/attributetag';
			// check if the request is a GET request for attributes with a specific tag (usually after clicking on an attributetag)
			if (substr($this->request->here, strlen($fullAddress), strlen($attributeTagQuery)) == $attributeTagQuery) {
				$attributeTagId = substr($this->request->here, (strlen($fullAddress) + strlen($attributeTagQuery) + 1));
				if (!is_numeric($attributeTagId)) {
					// either pagination active or no correct id
					unset($attributeTagId);
				}
			}

			// if this is no new search, get parameters from session
			if ($this->request->here != $fullAddress && !isset($attributeTagId)) {
				$keyword = $this->Session->read('paginate_conditions_keyword');
				$keyword2 = $this->Session->read('paginate_conditions_keyword2');
				$attributeTags = $this->Session->read('paginate_conditions_attributetags');
				$org = $this->Session->read('paginate_conditions_org');
				$type = $this->Session->read('paginate_conditions_type');
				$category = $this->Session->read('paginate_conditions_category');
				$tags = $this->Session->read('paginate_conditions_tags');
				$this->set('keywordSearch', $keyword);
				$this->set('keywordSearch2', $keyword2);
				$this->set('attributeTags', $attributeTags);
				$this->set('orgSearch', $org);
				$this->set('typeSearch', $type);
				$this->set('tags', $tags);
				$this->set('categorySearch', $category);
				$this->Attribute->contain(array('AttributeTag' => array('Tag')));

				// re-get pagination
				$this->Attribute->recursive = 0;
				$this->paginate = $this->Session->read('paginate_conditions');
				$attributes = $this->paginate();
				foreach ($attributes as $k => $attribute) {
					if (empty($attribute['Event']['id'])) {
						unset($attribute[$k]);
					}
				}
				$this->set('attributes', $attributes);

				// set the same view as the index page
				$this->render('index');
			} else {
				// reset the paginate_conditions
				$this->Session->write('paginate_conditions', array());
				$conditions = array();
				$alternateSearch = false;

				if (isset($attributeTagId)) {
					$this->loadModel('Tag');
					$this->Tag->id = $attributeTagId;
					if (!$this->Tag->exists()) {
						throw new NotFoundException(__('Invalid tag'));
					}

					$attributeTags = $this->Tag->find('first', array(
						'recursive' => -1,
						'conditions' => array(
							'id' => $attributeTagId
						)
					));
					$attributeTags = $attributeTags['Tag']['name'];
					$conditions['AND'][] = array('OR' => array('Attribute.id' => $this->Tag->findAttributeIdsByAttributeTagNames(array($attributeTags))));

					$keyword = null;
					$keyword2 = null;
					$org = null;
					$type = 'ALL';
					$tags = null;
					$category = 'ALL';
					$ioc = false;

					$this->set('keywordSearch', $keyword);
					$this->set('keywordSearch2', $keyword2);
				}

				if ($this->request->is('post')) {
					$keyword = $this->request->data['Attribute']['keyword'];
					$keyword2 = $this->request->data['Attribute']['keyword2'];
					$attributeTags = $this->request->data['Attribute']['attributetags'];
					$tags = $this->request->data['Attribute']['tags'];
					$org = $this->request->data['Attribute']['org'];
					$type = $this->request->data['Attribute']['type'];
					$ioc = $this->request->data['Attribute']['ioc'];
					$this->set('ioc', $ioc);
					$category = $this->request->data['Attribute']['category'];

					$keyWordText = null;
					$keyWordText2 = null;
					$keyWordText3 = null;

					// search the db
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
							$saveWord = trim(strtolower($keywordArrayElement));
							if ($saveWord != '') {
								$toInclude = true;
								if ($saveWord[0] == '!') {
									$toInclude = false;
									$saveWord = substr($saveWord, 1);
								}

								// check for an IPv4 address and subnet in CIDR notation (e.g. 127.0.0.1/8)
								if ($this->Cidr->checkCIDR($saveWord, 4)) {
									$cidrresults = $this->Cidr->CIDR($saveWord);
									foreach ($cidrresults as $result) {
										$result = strtolower($result);
										if (strpos($result, '|')) {
											$resultParts = explode('|', $result);
											if (!$toInclude) {
												$temp2[] = array(
													'AND' => array(
														'LOWER(Attribute.value1) NOT LIKE' => $resultParts[0],
														'LOWER(Attribute.value2) NOT LIKE' => $resultParts[1],
													));
											} else {
												$temp[] = array(
													'AND' => array(
														'LOWER(Attribute.value1)' => $resultParts[0],
														'LOWER(Attribute.value2)' => $resultParts[1],
													));
											}
										} else {
											if (!$toInclude) {
												array_push($temp2, array('LOWER(Attribute.value1) NOT LIKE' => $result));
												array_push($temp2, array('LOWER(Attribute.value2) NOT LIKE' => $result));
											} else {
												array_push($temp, array('LOWER(Attribute.value1) LIKE' => $result));
												array_push($temp, array('LOWER(Attribute.value2) LIKE' => $result));
											}
										}
									}
								} else {
									if (strpos($saveWord, '|')) {
										$resultParts = explode('|', $saveWord);
										if (!$toInclude) {
											$temp2[] = array(
												'AND' => array(
													'LOWER(Attribute.value1) NOT LIKE' => '%' . $resultParts[0],
													'LOWER(Attribute.value2) NOT LIKE' => $resultParts[1] . '%',
												));
										} else {
											$temp2[] = array(
												'AND' => array(
													'LOWER(Attribute.value1)' => '%' . $resultParts[0],
													'LOWER(Attribute.value2)' => $resultParts[1] . '%',
												));
										}
									} else {
										if (!$toInclude) {
											array_push($temp2, array('LOWER(Attribute.value1) NOT LIKE' => '%' . $saveWord . '%'));
											array_push($temp2, array('LOWER(Attribute.value2) NOT LIKE' => '%' . $saveWord . '%'));
										} else {
											array_push($temp, array('LOWER(Attribute.value1) LIKE' => '%' . $saveWord . '%'));
											array_push($temp, array('LOWER(Attribute.value2) LIKE' => '%' . $saveWord . '%'));
										}
									}
								}
								if ($toInclude) {
									array_push($temp, array('LOWER(Attribute.comment) LIKE' => '%' . $saveWord . '%'));
								} else {
									array_push($temp2, array('LOWER(Attribute.comment) NOT LIKE' => '%' . $saveWord . '%'));
								}
							}
							if ($i == 1 && $saveWord != '') {
								$keyWordText = $saveWord;
							} else if (($i > 1 && $i < 10) && $saveWord != '') {
								$keyWordText = $keyWordText . ', ' . $saveWord;
							} else if ($i == 10 && $saveWord != '') {
								$keyWordText = $keyWordText . ' and several other keywords';
							}
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
							if (empty($saveWord)) {
								continue;
							}
							if ($saveWord[0] == '!') {
								if (strlen(substr($saveWord, 1)) == 36) {
									$temp[] = array('Event.uuid !=' => substr($saveWord, 1));
									$temp[] = array('Attribute.uuid !=' => substr($saveWord, 1));
								} else {
									$temp[] = array('Attribute.event_id !=' => substr($saveWord, 1));
								}
							} else {
								if (strlen($saveWord) == 36) {
									$temp['OR'][] = array('Event.uuid =' => $saveWord);
									$temp['OR'][] = array('Attribute.uuid' => $saveWord);
								} else {
									$temp['OR'][] = array('Attribute.event_id =' => $saveWord);
								}
							}
							if ($i == 1 && $saveWord != '') {
								$keyWordText2 = $saveWord;
							} else if (($i > 1 && $i < 10) && $saveWord != '') {
								$keyWordText2 = $keyWordText2 . ', ' . $saveWord;
							} else if ($i == 10 && $saveWord != '') {
								$keyWordText2 = $keyWordText2 . ' and several other events';
							}
							$i++;
						}
						$this->set('keywordSearch2', $keyWordText2);
						if (!empty($temp)) {
							$conditions['AND'][] = $temp;
						}
					}

					if (!empty($attributeTags) || !empty($tags)) {
						$this->loadModel('Tag');
					}

					if (!empty($attributeTags)) {
						$includeAttributeTags = array();
						$excludeAttributeTags = array();
						$attributeTagsKeywordArray = explode("\n", $attributeTags);
						foreach ($attributeTagsKeywordArray as $tagName) {
							$tagName = trim($tagName);
							if (empty($tagName)) {
								continue;
							}
							if (substr($tagName, 0, 1) === '!') {
								$excludeAttributeTags[] = substr($tagName, 1);
							} else {
								$includeAttributeTags[] = $tagName;
							}
						}
						if (!empty($includeAttributeTags)) {
							$conditions['AND'][] = array('OR' => array('Attribute.id' => $this->Tag->findAttributeIdsByAttributeTagNames($includeAttributeTags)));
						}
						if (!empty($excludeAttributeTags)) {
							$conditions['AND'][] = array('Attribute.id !=' => $this->Tag->findAttributeIdsByAttributeTagNames($excludeAttributeTags));
						}
					}
					if (!empty($tags)) {
						$include = array();
						$exclude = array();
						$keywordArray = explode("\n", $tags);
						foreach ($keywordArray as $tagname) {
							$tagname = trim($tagname);
							if (empty($tagname)) {
								continue;
							}
							if (substr($tagname, 0, 1) === '!') {
								$exclude[] = substr($tagname, 1);
							} else {
								$include[] = $tagname;
							}
						}
						if (!empty($include)) {
							$conditions['AND'][] = array('OR' => array('Attribute.event_id' => $this->Tag->findEventIdsByTagNames($include)));
						}
						if (!empty($exclude)) {
							$conditions['AND'][] = array('Attribute.event_id !=' => $this->Tag->findEventIdsByTagNames($exclude));
						}
					}
					if ($type != 'ALL') {
						$conditions['Attribute.type ='] = $type;
					}
					if ($category != 'ALL') {
						$conditions['Attribute.category ='] = $category;
					}
					// organisation search field
					if (isset($org)) {
						$temp = array();
						$this->loadModel('Organisation');
						$orgArray = explode("\n", $org);
						foreach ($orgArray as $i => $orgArrayElement) {
							$saveWord = trim($orgArrayElement);
							if (empty($saveWord)) {
								continue;
							}
							if ($saveWord[0] == '!') {
								$org_names = $this->Organisation->find('all', array(
									'fields'     => array('id', 'name'),
									'conditions' => array('lower(name) LIKE' => '%' . strtolower(substr($saveWord, 1)) . '%'),
								));
								foreach ($org_names as $org_name) {
									$temp['AND'][] = array('Event.orgc_id !=' => $org_name['Organisation']['id']);
								}
							} else {
								$org_names = $this->Organisation->find('all', array(
									'fields'     => array('id', 'name'),
									'conditions' => array('lower(name) LIKE' => '%' . strtolower($saveWord) . '%'),
								));
								foreach ($org_names as $org_name) {
									$temp['OR'][] = array('Event.orgc_id' => $org_name['Organisation']['id']);
								}
							}
							if ($i == 0 && $saveWord != '') {
								$keyWordText3 = $saveWord;
							} else if (($i > 0 && $i < 9) && $saveWord != '') {
								$keyWordText3 = $keyWordText3 . ', ' . $saveWord;
							} else if ($i == 9 && $saveWord != '') {
								$keyWordText3 = $keyWordText3 . ' and several other organisations';
							}
						}
						$this->set('orgSearch', $keyWordText3);
						if (!empty($temp)) {
							$conditions['AND'][] = $temp;
						}
					}

					if ($this->request->data['Attribute']['alternate']) {
						$alternateSearch = true;
					}
				}

				if (isset($attributeTags)) {
					$this->set('attributeTags', $attributeTags);
				}
				$this->set('tags', $tags);
				$this->set('typeSearch', $type);
				$this->set('categorySearch', $category);

				$conditions['AND'][] = array('Attribute.deleted' => 0);
				if ($alternateSearch) {
					$events = $this->searchAlternate($conditions);
					$this->set('events', $events);
					$this->render('alternate_search_result');
				} else {
					$this->Attribute->recursive = 0;
					$this->paginate = array(
						'limit' => 60,
						'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 attributes?
						'conditions' => $conditions,
						'contain' => array(
							'Event' => array(
								'fields' => array(
									'orgc_id', 'id', 'org_id', 'user_id', 'info'
								)
							),
						)
					);
					$this->Attribute->contain(array('AttributeTag' => array('Tag')));
					if (!$this->_isSiteAdmin()) {
						// merge in private conditions
						$conditions = $this->Attribute->buildConditions($this->Auth->user());
						$this->paginate = Set::merge($this->paginate, array(
							'conditions' => $conditions
						));
					}
					$idList = array();
					$attributeIdList = array();
					$attributes = $this->paginate();
					$org_ids = array();
					foreach ($attributes as $k => $attribute) {
						if (empty($attribute['Event']['id'])) {
							unset($attribute[$k]);
							continue;
						}
						if ($attribute['Attribute']['type'] == 'attachment' && preg_match('/.*\.(jpg|png|jpeg|gif)$/i', $attribute['Attribute']['value'])) {
							$attributes[$k]['Attribute']['image'] = $this->Attribute->base64EncodeAttachment($attribute['Attribute']);
						}
						$org_ids[$attribute['Event']['org_id']] = false;
						$org_ids[$attribute['Event']['orgc_id']] = false;
					}
					$orgs = $this->Attribute->Event->Orgc->find('list', array(
							'conditions' => array('Orgc.id' => array_keys($org_ids)),
							'fields' => array('Orgc.id', 'Orgc.name')
					));
					$this->set('orgs', $orgs);
					$this->set('attributes', $attributes);

					// if we searched for IOCs only, apply the whitelist to the search result!
					if ($ioc) {
						$this->loadModel('Whitelist');
						$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
					}

					foreach ($attributes as $attribute) {
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
					if (isset($attributeTags))
						$this->Session->write('paginate_conditions_attributetags', $attributeTags);
					$this->Session->write('paginate_conditions_org', $org);
					$this->Session->write('paginate_conditions_type', $type);
					$this->Session->write('paginate_conditions_ioc', $ioc);
					$this->Session->write('paginate_conditions_tags', $tags);
					$this->Session->write('paginate_conditions_category', $category);
					$this->Session->write('search_find_idlist', $idList);
					$this->Session->write('search_find_attributeidlist', $attributeIdList);

					// set the same view as the index page
					$this->render('index');
				}
			}
		}
	}

	// If the checkbox for the alternate search is ticked, then this method is called to return the data to be represented
	// This alternate view will show a list of events with matching search results and the percentage of those matched attributes being marked as to_ids
	// events are sorted based on relevance (as in the percentage of matches being flagged as indicators for IDS)
	public function searchAlternate($data) {
		$attributes = $this->Attribute->fetchAttributes(
			$this->Auth->user(),
			array(
				'conditions' => array(
					'AND' => $data
				),
				'contain' => array('Event' => array('Orgc' => array('fields' => array('Orgc.name')))),
				'fields' => array(
					'Attribute.id', 'Attribute.event_id', 'Attribute.type', 'Attribute.category', 'Attribute.to_ids', 'Attribute.value', 'Attribute.distribution',
					'Event.id', 'Event.org_id', 'Event.orgc_id', 'Event.info', 'Event.distribution', 'Event.attribute_count', 'Event.date',
				)
			)
		);
		$events = array();
		foreach ($attributes as $attribute) {
			if (isset($events[$attribute['Event']['id']])) {
				if ($attribute['Attribute']['to_ids']) {
					$events[$attribute['Event']['id']]['to_ids']++;
				} else {
					$events[$attribute['Event']['id']]['no_ids']++;
				}
			} else {
				$events[$attribute['Event']['id']]['Event'] = $attribute['Event'];
				$events[$attribute['Event']['id']]['to_ids'] = 0;
				$events[$attribute['Event']['id']]['no_ids'] = 0;
				if ($attribute['Attribute']['to_ids']) {
					$events[$attribute['Event']['id']]['to_ids']++;
				} else {
					$events[$attribute['Event']['id']]['no_ids']++;
				}
			}
		}
		foreach ($events as $key => $event) {
			$events[$key]['relevance'] = 100 * $event['to_ids'] / ($event['no_ids'] + $event['to_ids']);
		}
		if (!empty($events)) $events = $this->__subval_sort($events, 'relevance');
		return $events;
	}

	// Sort the array of arrays based on a value of a sub-array
	private function __subval_sort($a,$subkey) {
		foreach ($a as $k=>$v) {
			$b[$k] = strtolower($v[$subkey]);
		}
		arsort($b);
		foreach ($b as $key=>$val) {
			$c[] = $a[$key];
		}
		return $c;
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
	public function restSearch($key = 'download', $value = false, $type = false, $category = false, $org = false, $tags = false, $from = false, $to = false, $last = false, $eventid = false, $withAttachments = false, $uuid = false, $publish_timestamp = false, $published = false, $timestamp = false, $enforceWarninglist = false, $to_ids = false, $deleted = false) {
		if ($tags) $tags = str_replace(';', ':', $tags);
		$simpleFalse = array('value' , 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted');
		foreach ($simpleFalse as $sF) {
			if (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false') ${$sF} = false;
		}
		if ($key != null && strlen($key) == 40) {
			$user = $this->checkAuthUser($key);
			if (!$user) {
				throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
			}
		} else {
			$key = strtolower($key);
			if (!$this->Auth->user()) throw new UnauthorizedException('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.');
		}
		// request handler for POSTed queries. If the request is a post, the parameters (apart from the key) will be ignored and replaced by the terms defined in the posted json or xml object.
		// The correct format for both is a "request" root element, as shown by the examples below:
		// For Json: {"request":{"value": "7.7.7.7&&1.1.1.1","type":"ip-src"}}
		// For XML: <request><value>7.7.7.7&amp;&amp;1.1.1.1</value><type>ip-src</type></request>
		// the response type is used to determine the parsing method (xml/json)
		if ($this->request->is('post')) {
			if ($this->response->type() === 'application/json') {
				if ($key == 'xml') {
					throw new MethodNotAllowedException('Content type and parameter mismatch. Expecting JSON.');
				}
				$data = $this->request->input('json_decode', true);
			} else if ($this->response->type() === 'application/xml' && !empty($this->request->data)) {
				if ($key == 'json') {
					throw new MethodNotAllowedException('Content type and parameter mismatch. Expecting XML.');
				}
				$data = $this->request->data;
			} else {
				throw new BadRequestException('Either specify the search terms in the url, or POST a json array / xml (with the root element being "request" and specify the correct accept and content type headers.');
			}
			if (!isset($data['request'])) {
				$data['request'] = $data;
			}
			$paramArray = array('value', 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'uuid', 'published', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
				else ${$p} = null;
			}
		}
		$simpleFalse = array('value' , 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted');
		foreach ($simpleFalse as $sF) {
			if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) ${$sF} = false;
		}

		if ($from) $from = $this->Attribute->Event->dateFieldCheck($from);
		if ($to) $to = $this->Attribute->Event->dateFieldCheck($to);
		if ($last) $last = $this->Attribute->Event->resolveTimeDelta($last);
		$conditions['AND'] = array();
		$subcondition = array();
		$this->loadModel('Attribute');
		// add the values as specified in the 2nd parameter to the conditions
		$parameters = array('value', 'type', 'category', 'org', 'eventid', 'uuid');
		foreach ($parameters as $k => $param) {
			if (isset(${$parameters[$k]}) && ${$parameters[$k]} !== false) {
				$conditions = $this->Attribute->setSimpleConditions($parameters[$k], ${$parameters[$k]}, $conditions);
			}
		}

		// If we sent any tags along, load the associated tag names for each attribute
		if ($tags) $conditions = $this->Attribute->setTagConditions($tags, $conditions, 'attribute');
		if ($from) $conditions['AND'][] = array('Event.date >=' => $from);
		if ($to) $conditions['AND'][] = array('Event.date <=' => $to);
		if ($publish_timestamp) $conditions = $this->Attribute->setPublishTimestampConditions($publish_timestamp, $conditions);
		if ($last) $conditions['AND'][] = array('Event.publish_timestamp >=' => $last);
		if ($published) $conditions['AND'][] = array('Event.published' => $published);
		if ($timestamp) $conditions['AND'][] = array('Attribute.timestamp >=' => $timestamp);
		if ($to_ids) $conditions = $this->Attribute->setToIDSConditions($to_ids, $conditions);
		// change the fields here for the attribute export!!!! Don't forget to check for the permissions, since you are not going through fetchevent. Maybe create fetchattribute?
		$params = array(
				'conditions' => $conditions,
				'fields' => array('Attribute.*', 'Event.org_id', 'Event.distribution'),
				'withAttachments' => $withAttachments,
				'enforceWarninglist' => $enforceWarninglist,
				'includeAllTags' => true,
				'flatten' => 1
		);
		if ($deleted) {
				$params['deleted'] = 1;
			if ($deleted === 'only') {
				$params['conditions']['AND'][] = array('Attribute.deleted' => 1);
			}
		}
		$results = $this->Attribute->fetchAttributes($this->Auth->user(), $params);
		$this->loadModel('Whitelist');
		$results = $this->Whitelist->removeWhitelistedFromArray($results, true);
		if ($key == 'openioc') {
			App::uses('IOCExportTool', 'Tools');
			$this->IOCExport = new IOCExportTool();
			$results = $this->IOCExport->buildAll($this->Auth->user(), $results, 'attribute');
		} else {
			if (!empty($results)) {
				$results = array('response' => array('Attribute' => $results));
				foreach ($results['response']['Attribute'] as $k => $v) {
					if (isset($results['response']['Attribute'][$k]['AttributeTag'])) {
						foreach ($results['response']['Attribute'][$k]['AttributeTag'] as $tk => $tag) {
							$results['response']['Attribute'][$k]['Attribute']['Tag'][$tk] = $tag['Tag'];
						}
					}
					$results['response']['Attribute'][$k] = $results['response']['Attribute'][$k]['Attribute'];
					unset(
							$results['response']['Attribute'][$k]['value1'],
							$results['response']['Attribute'][$k]['value2']
					);
				}
			} else {
				$results = array('response' => array());
			}
		}
		$responseType = $this->response->type();
		if ($key == 'openioc') {
			$responseType = 'openioc';
		}
		return $this->RestResponse->viewData($results, $responseType);
	}

	// returns an XML with attributes that belong to an event. The type of attributes to be returned can be restricted by type using the 3rd parameter.
	// Similar to the restSearch, this parameter can be chained with '&&' and negations are accepted too. For example filename&&!filename|md5 would return all filenames that don't have an md5
	// The usage of returnAttributes is the following: [MISP-url]/attributes/returnAttributes/<API-key>/<type>/<signature flag>
	// The signature flag is off by default, enabling it will only return attributes that have the to_ids flag set to true.
	public function returnAttributes($key='download', $id, $type = null, $sigOnly = false) {
		$user = $this->checkAuthUser($key);
		// if the user is authorised to use the api key then user will be populated with the user's account
		// in addition we also set a flag indicating whether the user is a site admin or not.
		if ($key != null && $key != 'download') {
			$user = $this->checkAuthUser($key);
		} else {
			if (!$this->Auth->user()) throw new UnauthorizedException('You are not authorized. Please send the Authorization header with your auth key along with an Accept header for application/xml.');
			$user = $this->checkAuthUser($this->Auth->user('authkey'));
		}
		if (!$user) {
			throw new UnauthorizedException('This authentication key is not authorized to be used for exports. Contact your administrator.');
		}
		if ($this->request->is('post')) {
			if ($this->response->type() === 'application/json') {
				$data = $this->request->input('json_decode', true);
			} else if ($this->response->type() === 'application/xml' && !empty($this->request->data)) {
				$data = $this->request->data;
			} else {
				throw new BadRequestException('Either specify the search terms in the url, or POST a json array / xml (with the root element being "request" and specify the correct accept and content type headers.');
			}
			$paramArray = array('type', 'sigOnly');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
				else ${$p} = null;
			}
		}
		$this->loadModel('Event');
		$this->Event->read(null, $id);
		$myEventOrAdmin = false;
		if ($user['User']['siteAdmin'] || $this->Event->data['Event']['org_id'] == $user['User']['org_id']) {
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
			foreach ($elements as $v) {
				if (substr($v, 0, 1) == '!') {
					$exclude[] = substr($v, 1);
				} else {
					$include[] = $v;
				}
			}
		}

		// check each attribute
		foreach ($this->Event->data['Attribute'] as $k => $attribute) {
			$contained = false;
			// If the include list is empty, then the first check should always set contained to true (basically we chose type = all - exclusions, or simply all)
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
		if ($key != null && $key != 'download') {
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
		if (!$this->Attribute->exists()) {
			throw new NotFoundException('Invalid attribute or no authorisation to view it.');
		}
		$this->Attribute->read(null, $id);
		if (!$user['User']['siteAdmin'] &&
			$user['User']['org_id'] != $this->Attribute->data['Event']['org_id'] &&
			($this->Attribute->data['Event']['distribution'] == 0 ||
				$this->Attribute->data['Attribute']['distribution'] == 0
			)) {
			throw new NotFoundException('Invalid attribute or no authorisation to view it.');
		}
		$this->__downloadAttachment($this->Attribute->data['Attribute']);
	}

	public function text($key='download', $type = 'all', $tags = false, $eventId = false, $allowNonIDS = false, $from = false, $to = false, $last = false, $enforceWarninglist = false, $allowNotPublished = false) {
		$simpleFalse = array('eventId', 'allowNonIDS', 'tags', 'from', 'to', 'last', 'enforceWarninglist', 'allowNotPublished');
		foreach ($simpleFalse as $sF) {
			if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) ${$sF} = false;
		}
		if ($type === 'null' || $type === '0' || $type === 'false') $type = 'all';
		if ($from) $from = $this->Attribute->Event->dateFieldCheck($from);
		if ($to) $to = $this->Attribute->Event->dateFieldCheck($to);
		if ($last) $last = $this->Attribute->Event->resolveTimeDelta($last);
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
		$attributes = $this->Attribute->text($this->Auth->user(), $type, $tags, $eventId, $allowNonIDS, $from, $to, $last, $enforceWarninglist, $allowNotPublished);
		$this->loadModel('Whitelist');
		$attributes = $this->Whitelist->removeWhitelistedFromArray($attributes, true);
		$this->set('attributes', $attributes);
		$this->render('/Attributes/text');
	}

	public function rpz($key='download', $tags=false, $eventId=false, $from=false, $to=false, $policy=false, $walled_garden = false, $ns = false, $email = false, $serial = false, $refresh = false, $retry = false, $expiry = false, $minimum_ttl = false, $ttl = false, $enforceWarninglist = false, $ns_alt = false) {
		// request handler for POSTed queries. If the request is a post, the parameters (apart from the key) will be ignored and replaced by the terms defined in the posted json or xml object.
		// The correct format for both is a "request" root element, as shown by the examples below:
		// For Json: {"request":{"policy": "walled-garden","garden":"garden.example.com"}}
		// For XML: <request><policy>walled-garden</policy><garden>garden.example.com</gargen></request>
		// the response type is used to determine the parsing method (xml/json)
		if ($this->request->is('post')) {
			if ($this->request->input('json_decode', true)) {
				$data = $this->request->input('json_decode', true);
			} else {
				$data = $this->request->data;
			}
			if (empty($data)) throw new BadRequestException('Either specify the search terms in the url, or POST a json array / xml (with the root element being "request" and specify the correct headers based on content type.');
			$paramArray = array('eventId', 'tags', 'from', 'to', 'policy', 'walled_garden', 'ns', 'email', 'serial', 'refresh', 'retry', 'expiry', 'minimum_ttl', 'ttl', 'enforceWarninglist', 'ns_alt');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
				else ${$p} = null;
			}
		}

		$simpleFalse = array('eventId', 'tags', 'from', 'to', 'policy', 'walled_garden', 'ns', 'email', 'serial', 'refresh', 'retry', 'expiry', 'minimum_ttl', 'ttl', 'enforceWarninglist', 'ns_alt');
		foreach ($simpleFalse as $sF) {
			if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) ${$sF} = false;
		}
		if (!in_array($policy, array('NXDOMAIN', 'NODATA', 'DROP', 'walled-garden'))) $policy = false;
		App::uses('RPZExport', 'Export');
		$rpzExport = new RPZExport();
		if ($policy) $policy = $rpzExport->getIdByPolicy($policy);

		$this->loadModel('Server');
		$rpzSettings = array();
		$lookupData = array('policy', 'walled_garden', 'ns', 'ns_alt', 'email', 'serial', 'refresh', 'retry', 'expiry', 'minimum_ttl', 'ttl');
		foreach ($lookupData as $v) {
			if (${$v} !== false) $rpzSettings[$v] = ${$v};
			else {
				$tempSetting = Configure::read('Plugin.RPZ_' . $v);
				if (isset($tempSetting)) $rpzSettings[$v] = Configure::read('Plugin.RPZ_' . $v);
				else $rpzSettings[$v] = $this->Server->serverSettings['Plugin']['RPZ_' . $v]['value'];
			}
		}
		if ($from) $from = $this->Attribute->Event->dateFieldCheck($from);
		if ($to) $to = $this->Attribute->Event->dateFieldCheck($to);
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
		if (false === $eventId) $eventIds = $this->Attribute->Event->fetchEventIds($this->Auth->user(), false, false, false, true);
		else if (is_numeric($eventId)) $eventIds = array($eventId);
		else throw new MethodNotAllowedException('Invalid event ID format.');
		$values = array();
		foreach ($eventIds as $k => $eventId) {
			$values = array_merge_recursive($values, $this->Attribute->rpz($this->Auth->user(), $tags, $eventId, $from, $to, $enforceWarninglist));
		}
		$this->response->type('txt');	// set the content type
		$file = '';
		if ($tags) $file = 'filtered.';
		if ($eventId) $file .= 'event-' . $eventId . '.';
		if ($from) $file .= 'from-' . $from . '.';
		if ($to) $file .= 'to-' . $to . '.';
		if ($file == '') $file = 'all.';
		$this->header('Content-Disposition: download; filename="misp.rpz.' . $file . 'txt"');
		$this->layout = 'text/default';
		$this->loadModel('Whitelist');
		foreach ($values as $key => $value) {
			$values[$key] = $this->Whitelist->removeWhitelistedValuesFromArray($value);
		}
		$this->set('values', $values);
		$this->set('rpzSettings', $rpzSettings);
		$this->render('/Attributes/rpz');
	}

	public function bro($key = 'download', $type = 'all', $tags = false, $eventId = false, $from = false, $to = false, $last = false, $enforceWarninglist = false) {
		if ($this->request->is('post')) {
			if ($this->request->input('json_decode', true)) {
				$data = $this->request->input('json_decode', true);
			} else {
				$data = $this->request->data;
			}
			if (!empty($data) && !isset($data['request'])) {
				$data = array('request' => $data);
			}
			$paramArray = array('type', 'tags', 'eventId', 'from', 'to', 'last', 'enforceWarninglist');
			foreach ($paramArray as $p) {
				if (isset($data['request'][$p])) ${$p} = $data['request'][$p];
			}
		}
		$simpleFalse = array('type', 'tags', 'eventId', 'from', 'to', 'last', 'enforceWarninglist');
		foreach ($simpleFalse as $sF) {
			if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) ${$sF} = false;
		}
		if ($type === 'null' || $type === '0' || $type === 'false') $type = 'all';
		if ($from) $from = $this->Attribute->Event->dateFieldCheck($from);
		if ($to) $to = $this->Attribute->Event->dateFieldCheck($to);
		if ($last) $last = $this->Attribute->Event->resolveTimeDelta($last);
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
		$filename = 'misp.' . $type . '.intel';
		if ($eventId) {
			$filename = 'misp.' . $type . '.event_' . $eventId . '.intel';
		}
		$responseFile = implode(PHP_EOL, $this->Attribute->bro($this->Auth->user(), $type, $tags, $eventId, $from, $to, $last, $enforceWarninglist)) . PHP_EOL;
		$this->response->body($responseFile);
		$this->response->type('txt');
		$this->response->download($filename);
		return $this->response;
	}

	public function reportValidationIssuesAttributes($eventId = false) {
		// TODO improve performance of this function by eliminating the additional SQL query per attribute
		// search for validation problems in the attributes
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$this->set('result', $this->Attribute->reportValidationIssuesAttributes($eventId));
	}

	public function generateCorrelation() {
		if (!self::_isSiteAdmin() || !$this->request->is('post')) throw new NotFoundException();
		if (!Configure::read('MISP.background_jobs')) {
			$k = $this->Attribute->generateCorrelation();
			$this->Session->setFlash(__('All done. ' . $k . ' attributes processed.'));
			$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
		} else {
			$job = ClassRegistry::init('Job');
			$job->create();
			$data = array(
					'worker' => 'default',
					'job_type' => 'generate correlation',
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
					array('jobGenerateCorrelation', $jobId),
					true
			);
			$job->saveField('process_id', $process_id);
			$this->Session->setFlash(__('Job queued. You can view the progress if you navigate to the active jobs view (administration -> jobs).'));
			$this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
		}
	}

	public function fetchViewValue($id, $field = null) {
		$validFields = array('value', 'comment', 'type', 'category', 'to_ids', 'distribution', 'timestamp');
		if (!isset($field) || !in_array($field, $validFields)) throw new MethodNotAllowedException('Invalid field requested.');
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This function can only be accessed via AJAX.');
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		$params = array(
				'conditions' => array('Attribute.id' => $id),
				'fields' => array('id', 'distribution', 'event_id', $field),
				'contain' => array(
						'Event' => array(
								'fields' => array('distribution', 'id', 'org_id'),
						)
				),
				'flatten' => 1
		);
		$attribute = $this->Attribute->fetchAttributes($this->Auth->user(), $params);
		if (empty($attribute)) throw new NotFoundException(__('Invalid attribute'));
		$attribute = $attribute[0];
		$result = $attribute['Attribute'][$field];
		if ($field == 'distribution') $result=$this->Attribute->shortDist[$result];
		if ($field == 'to_ids') $result = ($result == 0 ? 'No' : 'Yes');
		if ($field == 'timestamp') {
			if (isset($result)) $result = date('Y-m-d', $result);
			else echo '&nbsp';
		}
		$this->set('value', $result);
		$this->layout = 'ajax';
		$this->render('ajax/attributeViewFieldForm');
	}

	public function fetchEditForm($id, $field = null) {
		$validFields = array('value', 'comment', 'type', 'category', 'to_ids', 'distribution');
		if (!isset($field) || !in_array($field, $validFields)) throw new MethodNotAllowedException('Invalid field requested.');
		if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This function can only be accessed via AJAX.');
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
		$params = array(
			'conditions' => array('Attribute.id' => $id),
			'fields' => $fields,
			'flatten' => 1,
			'contain' => array(
				'Event' => array(
					'fields' => array('distribution', 'id', 'user_id', 'orgc_id'),
				)
			)
		);
		$attribute = $this->Attribute->fetchAttributes($this->Auth->user(), $params);
		if (empty($attribute)) throw new NotFoundException(__('Invalid attribute'));
		$attribute = $attribute[0];
		if (!$this->_isSiteAdmin()) {
			if ($attribute['Event']['orgc_id'] == $this->Auth->user('org_id')
			&& (($this->userRole['perm_modify'] && $attribute['Event']['user_id'] != $this->Auth->user('id'))
					|| $this->userRole['perm_modify_org'])) {
				// Allow the edit
			} else {
				throw new NotFoundException(__('Invalid attribute'));
			}
		}
		$this->layout = 'ajax';
		if ($field == 'distribution') {
			$distributionLevels = $this->Attribute->shortDist;
			unset($distributionLevels[4]);
			$this->set('distributionLevels', $distributionLevels);
		}
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


	public function attributeReplace($id) {
		if (!$this->userRole['perm_add']) {
			throw new MethodNotAllowedException('Event not found or you don\'t have permissions to create attributes');
		}
		$event = $this->Attribute->Event->find('first', array(
				'conditions' => array('Event.id' => $id),
				'fields' => array('id', 'orgc_id', 'distribution'),
				'recursive' => -1
		));
		if (empty($event) || (!$this->_isSiteAdmin() && ($event['Event']['orgc_id'] != $this->Auth->user('org_id') || !$this->userRole['perm_add']))) throw new MethodNotAllowedException('Event not found or you don\'t have permissions to create attributes');
		$this->set('event_id', $id);
		if ($this->request->is('get')) {
			$this->layout = 'ajax';
			$this->request->data['Attribute']['event_id'] = $id;

			// combobox for types
			$types = array_keys($this->Attribute->typeDefinitions);
			$types = $this->_arrayToValuesIndexArray($types);
			$this->set('types', $types);
			// combobox for categories
			$categories = array_keys($this->Attribute->categoryDefinitions);
			$categories = $this->_arrayToValuesIndexArray($categories);
			$this->set('categories', compact('categories'));
			$this->set('attrDescriptions', $this->Attribute->fieldDescriptions);
			$this->set('typeDefinitions', $this->Attribute->typeDefinitions);
			$this->set('categoryDefinitions', $this->Attribute->categoryDefinitions);
		}
		if ($this->request->is('post')) {
			if (!$this->request->is('ajax')) throw new MethodNotAllowedException('This action can only be accessed via AJAX.');

			$newValues = explode(PHP_EOL, $this->request->data['Attribute']['value']);
			$category = $this->request->data['Attribute']['category'];
			$type = $this->request->data['Attribute']['type'];
			$to_ids = $this->request->data['Attribute']['to_ids'];

			if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $event['Event']['orgc_id'] && !$this->userRole['perm_add']) throw new MethodNotAllowedException('You are not authorised to do that.');

			$oldAttributes = $this->Attribute->find('all', array(
					'conditions' => array(
							'event_id' => $id,
							'category' => $category,
							'type' => $type,
					),
					'fields' => array('id', 'event_id', 'category', 'type', 'value'),
					'recursive' => -1,
			));
			$results = array('untouched' => count($oldAttributes), 'created' => 0, 'deleted' => 0, 'createdFail' => 0, 'deletedFail' => 0);

			$newValues = array_map('trim', $newValues);

			foreach ($newValues as $value) {
				$found = false;
				foreach ($oldAttributes as $old) {
					if ($value == $old['Attribute']['value']) {
						$found = true;
					}
				}
				if (!$found) {
					$attribute = array(
							'value' => $value,
							'event_id' => $id,
							'category' => $category,
							'type' => $type,
							'distribution' => $event['Event']['distribution'],
							'to_ids' => $to_ids,
					);
					$this->Attribute->create();
					if ($this->Attribute->save(array('Attribute' => $attribute))) {
						$results['created']++;
					} else {
						$results['createdFail']++;
					}
				}
			}

			foreach ($oldAttributes as $old) {
				if (!in_array($old['Attribute']['value'], $newValues)) {
					if ($this->Attribute->delete($old['Attribute']['id'])) {
						$results['deleted']++;
						$results['untouched']--;
					} else {
						$results['deletedFail']++;
					}
				}
			}
			$message = '';
			$success = true;
			if (($results['created'] > 0 || $results['deleted'] > 0) && $results['createdFail'] == 0 && $results['deletedFail'] == 0) {
				$message .= 'Update completed without any issues.';
				$event = $this->Attribute->Event->find('first', array(
					'conditions' => array('Event.id' => $id),
					'recursive' => -1
				));
				$event['Event']['published'] = 0;
				$date = new DateTime();
				$event['Event']['timestamp'] = $date->getTimestamp();
				$this->Attribute->Event->save($event);
			} else {
				$message .= 'Update completed with some errors.';
				$success = false;
			}

			if ($results['created']) $message .= $results['created'] . ' attribute' . $this->__checkCountForOne($results['created']) . ' created. ';
			if ($results['createdFail']) $message .= $results['createdFail'] . ' attribute' . $this->__checkCountForOne($results['createdFail']) . ' could not be created. ';
			if ($results['deleted']) $message .= $results['deleted'] . ' attribute' . $this->__checkCountForOne($results['deleted']) . ' deleted.';
			if ($results['deletedFail']) $message .= $results['deletedFail'] . ' attribute' . $this->__checkCountForOne($results['deletedFail']) . ' could not be deleted. ';
			$message .= $results['untouched'] . ' attributes left untouched. ';

			$this->autoRender = false;
			$this->layout = 'ajax';
			if ($success) return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message)), 'status'=>200, 'type' => 'json'));
			else return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'errors' => $message)), 'status'=>200, 'type' => 'json'));
		}
	}

	private function __checkCountForOne($number) {
		if ($number != 1) return 's';
		return '';
	}


	// download a sample by passing along an md5
	public function downloadSample($hash=false, $allSamples=false, $eventID=false) {
		if (!$this->userRole['perm_auth']) throw new MethodNotAllowedException('This functionality requires API key access.');
		$error = false;
		if ($this->response->type() === 'application/json') {
			$data = $this->request->input('json_decode', true);
		} else if ($this->response->type() === 'application/xml') {
			$data = $this->request->data;
		} else {
			throw new BadRequestException('This action is for the API only. Please refer to the automation page for information on how to use it.');
		}
		if (!$hash && isset($data['request']['hash'])) $hash = $data['request']['hash'];
		if (!$allSamples && isset($data['request']['allSamples'])) $allSamples = $data['request']['allSamples'];
		if (!$eventID && isset($data['request']['eventID'])) $eventID = $data['request']['eventID'];
		if (!$eventID && !$hash) throw new MethodNotAllowedException('No hash or event ID received. You need to set at least one of the two.');
		if (!$hash) $allSamples = true;


		$simpleFalse = array('hash', 'allSamples', 'eventID');
		foreach ($simpleFalse as $sF) {
			if (!is_array(${$sF}) && (${$sF} === 'null' || ${$sF} == '0' || ${$sF} === false || strtolower(${$sF}) === 'false')) ${$sF} = false;
		}

		// valid combinations of settings are:
		// hash
		// eventID + all samples
		// hash + eventID
		// hash + eventID + all samples

		$searchConditions = array();
		$types = array();
		if ($hash) {
			$validTypes = $this->Attribute->resolveHashType($hash);
			if ($allSamples) {
				if (empty($validTypes)) {
					$error = 'Invalid hash format (valid options are ' . implode(', ', array_keys($this->Attribute->hashTypes)) . ')';
				} else {
					foreach ($validTypes as $t) {
						if ($t == 'md5') $types = array_merge($types, array('malware-sample', 'filename|md5', 'md5'));
						else $types = array_merge($types, array('filename|' . $t, $t));
					}
				}
				if (empty($error)) {
					$event_ids = $this->Attribute->find('list', array(
						'recursive' => -1,
						'contain' => array('Event'),
						'fields' => array('Event.id'),
						'conditions' => array(
							'OR' => array(
								'AND' => array(
									'LOWER(Attribute.value1) LIKE' => strtolower($hash),
									'Attribute.value2' => '',
								),
								'LOWER(Attribute.value2) LIKE' => strtolower($hash)
							)
						),
					));
					$searchConditions = array(
						'AND' => array('Event.id' => array_values($event_ids))
					);
					if (empty($event_ids)) $error = 'No hits with the given parameters.';
				}
			} else {
				if (!in_array('md5', $validTypes)) $error = 'Only MD5 hashes can be used to fetch malware samples at this point in time.';
				if (empty($error)) {
					$searchConditions = array('AND' => array('LOWER(Attribute.value2) LIKE' => strtolower($hash)));
				}
			}
		}

		if (!empty($eventID)) $searchConditions['AND'][] = array('Event.id' => $eventID);

		if (empty($error)) {
			$attributes = $this->Attribute->fetchAttributes(
					$this->Auth->user(),
					array(
						'fields' => array('Attribute.event_id', 'Attribute.id', 'Attribute.value1', 'Attribute.value2', 'Event.info'),
						'conditions' => array(
							'AND' => array(
								$searchConditions,
								array('Attribute.type' => 'malware-sample')
							)
						),
						'contain' => array('Event'),
						'flatten' => 1
					)
			);
			if (empty($attributes)) $error = 'No hits with the given parameters.';

			$results = array();
			foreach ($attributes as $attribute) {
				$found = false;
				foreach ($results as $previous) {
					if ($previous['md5'] == $attribute['Attribute']['value2']) $found = true;
				}
				if (!$found) {
					$results[] = array(
						'md5' => $attribute['Attribute']['value2'],
						'base64' => $this->Attribute->base64EncodeAttachment($attribute['Attribute']),
						'filename' => $attribute['Attribute']['value1'],
						'attribute_id' => $attribute['Attribute']['id'],
						'event_id' => $attribute['Attribute']['event_id'],
						'event_info' => $attribute['Event']['info'],
					);
				}
			}
			if ($error) {
				$this->set('message', $error);
				$this->set('_serialize', array('message'));
			} else {
				$this->set('result', $results);
				$this->set('_serialize', array('result'));
			}
		} else {
			$this->set('message', $error);
			$this->set('_serialize', array('message'));
		}
	}

	public function pruneOrphanedAttributes() {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException('You are not authorised to do that.');
		$events = array_keys($this->Attribute->Event->find('list'));
		$orphans = $this->Attribute->find('list', array('conditions' => array('Attribute.event_id !=' => $events)));
		if (count($orphans) > 0) $this->Attribute->deleteAll(array('Attribute.event_id !=' => $events), false, true);
		$this->Session->setFlash('Removed ' . count($orphans) . ' attribute(s).');
		$this->redirect(Router::url($this->referer(), true));
	}

	public function checkOrphanedAttributes() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException('You are not authorised to do that.');
		$this->loadModel('Attribute');
		$events = array_keys($this->Attribute->Event->find('list'));
		$orphans = $this->Attribute->find('list', array('conditions' => array('Attribute.event_id !=' => $events)));
		return new CakeResponse(array('body'=> count($orphans), 'status'=>200, 'type' => 'json'));
	}

	public function updateAttributeValues($script) {
		if (!$this->_isSiteAdmin() || !$this->request->is('post')) throw new MethodNotAllowedException('You are not authorised to do that.');
		switch ($script) {
			case 'urlSanitisation':
				$replaceConditions = array(
					array('search' => 'UPPER(Attribute.value1) LIKE', 'from' => 'HXXP', 'to' => 'http', 'ci' => true, 'condition' => 'startsWith'),
					array('search' => 'Attribute.value1 LIKE', 'from' => '[.]', 'to' => '.', 'ci' => false, 'condition' => 'contains'),
				);
				break;
			default:
				throw new Exception('Invalid script.');
		}
		$counter = 0;
		foreach ($replaceConditions as $rC) {
			$searchPattern = '';
			if (in_array($rC['condition'], array('endsWith', 'contains'))) $searchPattern .= '%';
			$searchPattern .= $rC['from'];
			if (in_array($rC['condition'], array('startsWith', 'contains'))) $searchPattern .= '%';
			$attributes = $this->Attribute->find('all', array('conditions' => array($rC['search'] => $searchPattern), 'recursive' => -1));
			foreach ($attributes as $attribute) {
				$regex = '/';
				if (!in_array($rC['condition'], array('startsWith', 'contains'))) $regex .= '^';
				$regex .= $rC['from'];
				if (!in_array($rC['condition'], array('endsWith', 'contains'))) $regex .= '$';
				$regex .= '/';
				if ($rC['ci']) $regex .= 'i';
				$attribute['Attribute']['value'] = preg_replace($regex, $rC['to'], $attribute['Attribute']['value']);
				$this->Attribute->save($attribute);
				$counter++;
			}
		}
		$this->Session->setFlash('Updated ' . $counter . ' attribute(s).');
		$this->redirect('/pages/display/administration');
	}

	public function hoverEnrichment($id) {
		$attribute = $this->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id)));
		if (empty($attribute)) throw new NotFoundException('Invalid Attribute');
		$this->loadModel('Server');
		$this->loadModel('Module');
		$modules = $this->Module->getEnabledModules($this->Auth->user());
		$validTypes = array();
		if (isset($modules['hover_type'][$attribute[0]['Attribute']['type']])) {
			$validTypes = $modules['hover_type'][$attribute[0]['Attribute']['type']];
		}
		$url = Configure::read('Plugin.Enrichment_services_url') ? Configure::read('Plugin.Enrichment_services_url') : $this->Server->serverSettings['Plugin']['Enrichment_services_url']['value'];
		$port = Configure::read('Plugin.Enrichment_services_port') ? Configure::read('Plugin.Enrichment_services_port') : $this->Server->serverSettings['Plugin']['Enrichment_services_port']['value'];
		$resultArray = array();
		foreach ($validTypes as $type) {
			$options = array();
			$found = false;
			foreach ($modules['modules'] as $temp) {
				if ($temp['name'] == $type) {
					$found = true;
					if (isset($temp['meta']['config'])) {
						foreach ($temp['meta']['config'] as $conf) $options[$conf] = Configure::read('Plugin.Enrichment_' . $type . '_' . $conf);
					}
				}
			}
			if (!$found) throw new MethodNotAllowedException('No valid enrichment options found for this attribute.');
			$data = array('module' => $type, $attribute[0]['Attribute']['type'] => $attribute[0]['Attribute']['value']);
			if (!empty($options)) $data['config'] = $options;
			$data = json_encode($data);
			$result = $this->Module->queryModuleServer('/query', $data, true);
			if ($result) {
				if (!is_array($result)) {
					$resultArray[] = array($type => $result);
				}
			} else {
				$resultArray[] = array($type => 'Enrichment service not reachable.');
				continue;
			}
			if (!is_array($result)) {
				$resultArray[] =  array($type => $result);
				continue;
			}
			if (!empty($result['results'])) {
				foreach ($result['results'] as $r) {
					if (is_array($r['values']) && !empty($r['values'])) {
						$tempArray = array();
						foreach ($r['values'] as $k => $v) {
							if (is_array($v)) $v = 'Array returned';
							$tempArray[] = $k . ': ' . $v;
						}
						$resultArray[] = array($type => $tempArray);
					} else if ($r['values'] == null) $resultArray[] = array($type => 'No result');
					else $resultArray[] = array($type => $r['values']);
				}
			}
		}
		$this->set('results', $resultArray);
		$this->layout = 'ajax';
		$this->render('ajax/hover_enrichment');
	}

	public function describeTypes() {
		$result = array();
		foreach ($this->Attribute->typeDefinitions as $key => $value) {
			$result['sane_defaults'][$key] = array('default_category' => $value['default_category'], 'to_ids' => $value['to_ids']);
		}
		$result['types'] = array_keys($this->Attribute->typeDefinitions);
		$result['categories'] = array_keys($this->Attribute->categoryDefinitions);
		foreach ($this->Attribute->categoryDefinitions as $cat => $data) {
			$result['category_type_mappings'][$cat] = $data['types'];
		}
		$this->set('result', $result);
		$this->set('_serialize', array('result'));
	}

	public function attributeStatistics($type = 'type', $percentage = false) {
		$validTypes = array('type', 'category');
		if (!in_array($type, $validTypes)) throw new MethodNotAllowedException('Invalid type requested.');
		$totalAttributes = $this->Attribute->find('count', array());
		$attributes = $this->Attribute->find('all', array(
				'recursive' => -1,
				'fields' => array($type, 'COUNT(id) as attribute_count'),
				'group' => array($type)
		));
		$results = array();
		foreach ($attributes as $attribute) {
			if ($percentage) {
				$results[$attribute['Attribute'][$type]] = round(100 * $attribute[0]['attribute_count'] / $totalAttributes, 3) . '%';
			} else {
				$results[$attribute['Attribute'][$type]] = $attribute[0]['attribute_count'];
			}
		}
		ksort($results);
		$this->autoRender = false;
		$this->layout = false;
		$this->set('data', $results);
		$this->set('flags', JSON_PRETTY_PRINT);
		$this->response->type('json');
		$this->render('/Servers/json/simple');
	}

	public function addTag($id = false, $tag_id = false) {
		if (!$this->request->is('post')) {
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that. Only POST requests are accepted.')), 'status' => 200, 'type' => 'json'));
		}

		$rearrangeRules = array(
			'request' => false,
			'Attribute' => false,
			'tag_id' => 'tag',
			'attribute_id' => 'attribute',
			'id' => 'attribute'
		);
		$RearrangeTool = new RequestRearrangeTool();
		$this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
		if ($id === false) {
			$id = $this->request->data['attribute'];
		}
		if ($id === 'selected') {
			$idList = json_decode($this->request->data['attribute_ids'], true);
		}
		if ($tag_id === false) $tag_id = $this->request->data['tag'];
		if (!is_numeric($tag_id)) {
			$tag = $this->Attribute->AttributeTag->Tag->find('first', array('recursive' => -1, 'conditions' => array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)))));
			if (empty($tag)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status' => 200, 'type' => 'json'));
			$tag_id = $tag['Tag']['id'];
		}
		if (!isset($idList)) {
			$idList = array($id);
		}
		$success = 0;
		$fails = 0;
		foreach ($idList as $id) {
			$this->Attribute->id = $id;
			if (!$this->Attribute->exists()) throw new NotFoundException(__('Invalid attribute'));
			$this->Attribute->read();
			if ($this->Attribute->data['Attribute']['deleted']) throw new NotFoundException(__('Invalid attribute'));
			$eventId = $this->Attribute->data['Attribute']['event_id'];

			$this->Attribute->Event->recursive = -1;
			$event = $this->Attribute->Event->read(array(), $eventId);
			if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
				if (!$this->userRole['perm_tagger'] || ($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'])) {
					return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status' => 200, 'type' => 'json'));
				}
			}

			$this->Attribute->recursive = -1;
			$this->Attribute->AttributeTag->Tag->id = $tag_id;
			if (!$this->Attribute->AttributeTag->Tag->exists()) {
				return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status' => 200, 'type' => 'json'));
			}
			$tag = $this->Attribute->AttributeTag->Tag->find('first', array(
				'conditions' => array('Tag.id' => $tag_id),
				'recursive' => -1,
				'fields' => array('Tag.name')
			));
			$found = $this->Attribute->AttributeTag->find('first', array(
				'conditions' => array(
					'attribute_id' => $id,
					'tag_id' => $tag_id
				),
				'recursive' => -1,
			));
			$this->autoRender = false;
			if (!empty($found)) {
				$fails++;
				continue;
			}
			$this->Attribute->AttributeTag->create();
			if ($this->Attribute->AttributeTag->save(array('attribute_id' => $id, 'tag_id' => $tag_id, 'event_id' => $eventId))) {
				$event['Event']['published'] = 0;
				$date = new DateTime();
				$event['Event']['timestamp'] = $date->getTimestamp();
				$this->Attribute->Event->save($event);
				$this->Attribute->data['Attribute']['timestamp'] = $date->getTimestamp();
				$this->Attribute->save($this->Attribute->data);
				$log = ClassRegistry::init('Log');
				$log->createLogEntry($this->Auth->user(), 'tag', 'Attribute', $id, 'Attached tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" to attribute (' . $id . ')', 'Attribute (' . $id . ') tagged as Tag (' . $tag_id . ')');
				$success++;
			} else {
				$fails++;
			}
		}
		if ($fails == 0) {
			if ($success == 1) {
				$message = 'Tag added.';
			} else {
				$message = $success . ' tags added.';
			}
			return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => $message, 'check_publish' => true)), 'status' => 200, 'type' => 'json'));
		} else {
			if ($fails == 1) {
				$message = 'Tag could not be added.';
			} else {
				$message = $fails . ' tags could not be added.';
			}
			if ($success > 0) {
				$message .= ' However, ' . $success . ' tag(s) were added.';
			}
			return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $message)), 'status' => 200, 'type' => 'json'));
		}
	}

	public function removeTag($id = false, $tag_id = false) {
		if (!$this->request->is('post')) {
			$this->set('id', $id);
			$this->set('tag_id', $tag_id);
			$this->set('model', 'Attribute');
			$this->render('ajax/tagRemoveConfirmation');
		} else {
			$rearrangeRules = array(
				'request' => false,
				'Attribute' => false,
				'tag_id' => 'tag',
				'attribute_id' => 'attribute',
				'id' => 'attribute'
			);
			$RearrangeTool = new RequestRearrangeTool();
			$this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
			if ($id === false) $id = $this->request->data['attribute'];
			if ($tag_id === false) $tag_id = $this->request->data['tag'];
			$this->Attribute->id = $id;
			if (!$this->Attribute->exists()) throw new NotFoundException(__('Invalid attribute'));
			$this->Attribute->read();
			if ($this->Attribute->data['Attribute']['deleted']) throw new NotFoundException(__('Invalid attribute'));
			$eventId = $this->Attribute->data['Attribute']['event_id'];
			if (empty($tag_id)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status' => 200, 'type' => 'json'));
			if (!is_numeric($tag_id)) {
				$tag = $this->Attribute->AttributeTag->Tag->find('first', array('recursive' => -1, 'conditions' => array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)))));
				if (empty($tag)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status' => 200, 'type' => 'json'));
				$tag_id = $tag['Tag']['id'];
			}
			if (!is_numeric($id)) $id = $this->request->data['Attribute']['id'];

			$this->Attribute->Event->recursive = -1;
			$event = $this->Attribute->Event->read(array(), $eventId);
			// org should allow to (un)tag too, so that an event that gets pushed can be (un)tagged locally by the owning org
			if ((($this->Auth->user('org_id') !== $event['Event']['org_id'] && $this->Auth->user('org_id') !== $event['Event']['orgc_id'] && $event['Event']['distribution'] == 0) || (!$this->userRole['perm_tagger'])) && !$this->_isSiteAdmin()) {
				return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status' => 200, 'type' => 'json'));
			}

			$this->Attribute->recursive = -1;
			$attributeTag = $this->Attribute->AttributeTag->find('first', array(
				'conditions' => array(
					'attribute_id' => $id,
					'tag_id' => $tag_id
				),
				'recursive' => -1,
			));
			$this->autoRender = false;
			if (empty($attributeTag)) return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid attribute - tag combination.')), 'status' => 200, 'type' => 'json'));
			$tag = $this->Attribute->AttributeTag->Tag->find('first', array(
				'conditions' => array('Tag.id' => $tag_id),
				'recursive' => -1,
				'fields' => array('Tag.name')
			));
			if ($this->Attribute->AttributeTag->delete($attributeTag['AttributeTag']['id'])) {
				$event['Event']['published'] = 0;
				$date = new DateTime();
				$event['Event']['timestamp'] = $date->getTimestamp();
				$this->Attribute->Event->save($event);
				$this->Attribute->data['Attribute']['timestamp'] = $date->getTimestamp();
				$this->Attribute->save($this->Attribute->data);
				$log = ClassRegistry::init('Log');
				$log->createLogEntry($this->Auth->user(), 'tag', 'Attribute', $id, 'Removed tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" from attribute (' . $id . ')', 'Attribute (' . $id . ') untagged of Tag (' . $tag_id . ')');
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Tag removed.', 'check_publish' => true)), 'status' => 200));
			} else {
				return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Tag could not be removed.')), 'status' => 200, 'type' => 'json'));
			}
		}
	}

	public function toggleCorrelation($id) {
		if (!$this->_isSiteAdmin() && Configure.read('MISP.allow_disabling_correlation')) {
			throw new MethodNotAllowedException('Disabling the correlation is not permitted on this instance.');
		}
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException('Invalid Attribute.');
		}
		if (!$this->Auth->user('Role')['perm_modify']) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		$conditions = array('Attribute.id' => $id);
		if (!$this->_isSiteAdmin()) {
			$conditions['Event.orgc_id'] = $this->Auth->user('org_id');
		}
		$attribute = $this->Attribute->find('first', array(
			'conditions' => $conditions,
			'recursive' => -1,
			'contain' => array('Event')
		));
		if (empty($attribute)) {
			throw new NotFoundException('Invalid Attribute.');
		}
		if (!$this->Auth->user('Role')['perm_modify_org'] && $this->Auth->user('id') != $attribute['Event']['user_id']) {
			throw new MethodNotAllowedException('You don\'t have permission to do that.');
		}
		if ($this->request->is('post')) {
			if ($attribute['Attribute']['disable_correlation']) {
				$attribute['Attribute']['disable_correlation'] = 0;
				$this->Attribute->save($attribute);
				$this->Attribute->__afterSaveCorrelation($attribute['Attribute'], false, $attribute);
			} else {
				$attribute['Attribute']['disable_correlation'] = 1;
				$this->Attribute->save($attribute);
				$this->Attribute->purgeCorrelations($attribute['Event']['id'], $attribute['Attribute']['id']);
			}
			if ($this->_isRest()) {
				return $this->RestResponse->saveSuccessResponse('attributes', 'toggleCorrelation', $id, false, 'Correlation ' . ($attribute['Attribute']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
			} else {
				return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => ('Correlation ' . ($attribute['Attribute']['disable_correlation'] ? 'disabled' : 'enabled')), 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
			}
		} else {
			$this->set('attribute', $attribute);
			$this->render('ajax/toggle_correlation');
		}
	}

	public function checkAttachments() {
			$attributes = $this->Attribute->find('all', array(
					'conditions' => array('Attribute.type' => array('attachment', 'malware-sample')),
					'recursive' => -1)
			);
			$counter = 0;
			$attachments_dir = Configure::read('MISP.attachments_dir');
			if (empty($attachments_dir)) {
				$this->loadModel('Server');
				$attachments_dir = $this->Server->getDefaultAttachments_dir();
			}
			foreach ($attributes as $attribute) {
					$path = $attachments_dir . DS . $attribute['Attribute']['event_id'] . DS;
					$file = $attribute['Attribute']['id'];
					if (!file_exists($path . $file)) {
							$counter++;
					}
			}
			return new CakeResponse(array('body'=>$counter, 'status'=>200));
	}
}
