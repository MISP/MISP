<?php

App::uses('AppModel', 'Model');

class MispObject extends AppModel {

	public $name = 'Object';
	public $alias = 'Object';

	public $useTable = 'objects';

	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
				'userModel' => 'User',
				'userKey' => 'user_id',
				'change' => 'full'),
	);

	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'event_id'
		),
		'SharingGroup' => array(
			'className' => 'SharingGroup',
			'foreignKey' => 'sharing_group_id'
		),
		'ObjectTemplate' => array(
			'className' => 'ObjectTemplate',
			'foreignKey' => false,
			'dependent' => false,
			'conditions' => array('MispObject.template_uuid' => 'ObjectTemplate.uuid')
		)
	);

	public $hasMany = array(
		'Attribute' => array(
			'className' => 'Attribute',
			'dependent' => true,
		),
		'ObjectReference' => array(
			'className' => 'ObjectReference',
			'dependent' => true,
			'foreignKey' => 'object_id'
		),
	);

	public $validate = array(
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		if (empty($this->data[$this->alias]['comment'])) {
			$this->data[$this->alias]['comment'] = "";
		}
		// generate UUID if it doesn't exist
		if (empty($this->data[$this->alias]['uuid'])) {
			$this->data[$this->alias]['uuid'] = CakeText::uuid();
		}
		// generate timestamp if it doesn't exist
		if (empty($this->data[$this->alias]['timestamp'])) {
			$date = new DateTime();
			$this->data[$this->alias]['timestamp'] = $date->getTimestamp();
		}
		if (empty($this->data[$this->alias]['template_version'])) {
			$this->data[$this->alias]['template_version'] = 1;
		}
		if (isset($this->data[$this->alias]['deleted']) && empty($this->data[$this->alias]['deleted'])) {
			$this->data[$this->alias]['deleted'] = 0;
		}
 		if (!isset($this->data[$this->alias]['distribution']) || $this->data['Object']['distribution'] != 4) $this->data['Object']['sharing_group_id'] = 0;
		if (!isset($this->data[$this->alias]['distribution'])) $this->data['Object']['distribution'] = 5;
		return true;
	}

	public function afterSave($created, $options = array()) {
		if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_attribute_notifications_enable')) {
			if (empty($this->data['Object']['skip_zmq'])) {
				$pubSubTool = $this->getPubSubTool();
				$object = $this->find('first', array(
					'conditions' => array('Object.id' => $this->id),
					'recursive' => -1
				));
				$action = $created ? 'add' : 'edit';
				if (!empty($this->data['Object']['deleted'])) $action = 'soft-delete';
				$pubSubTool->object_save($object, $action);
			}
		}
		return true;
	}

	public function beforeDelete($cascade = true) {
		if (!empty($this->data['Object']['id'])) {
			if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_object_notifications_enable')) {
				$pubSubTool = $this->getPubSubTool();
				$object = $this->find('first', array(
					'recursive' => -1,
					'conditions' => array('Object.id' => $this->data['Object']['id'])
				));
				$pubSubTool->object_save($object, 'delete');
			}
		}
	}

	public function afterDelete() {
		if (!empty($this->data[$this->alias]['id'])) {
			$this->ObjectReference->deleteAll(
				array(
					'ObjectReference.referenced_type' => 1,
					'ObjectReference.referenced_id' => $this->data[$this->alias]['id'],
				),
				false
			);
		}
	}

	public function saveObject($object, $eventId, $template, $user, $errorBehaviour = 'drop') {
		$this->create();
		$templateFields = array(
			'name' => 'name',
			'meta-category' => 'meta-category',
			'description' => 'description',
			'template_version' => 'version',
			'template_uuid' => 'uuid'
		);
		foreach ($templateFields as $k => $v) {
				$object['Object'][$k] = $template['ObjectTemplate'][$v];
		}
		$object['Object']['event_id'] = $eventId;
		$result = false;
		if ($this->save($object)) {
			$id = $this->id;
			foreach ($object['Attribute'] as $k => $attribute) {
				$object['Attribute'][$k]['object_id'] = $id;
			}
			$result = $this->Attribute->saveAttributes($object['Attribute']);
		} else {
			$result = $this->validationErrors;
		}
		return $id;
	}

	public function buildEventConditions($user, $sgids = false) {
		if ($user['Role']['perm_site_admin']) return array();
		if ($sgids == false) {
			$sgsids = $this->SharingGroup->fetchAllAuthorised($user);
		}
		return array(
			'OR' => array(
				array(
					'AND' => array(
						'Event.distribution >' => 0,
						'Event.distribution <' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published' => 1) : array(),
					),
				),
				array(
					'AND' => array(
						'Event.sharing_group_id' => $sgids,
						'Event.distribution' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published' => 1) : array(),
					)
				)
			)
		);
	}

	public function buildConditions($user, $sgids = false) {
		$conditions = array();
		if (!$user['Role']['perm_site_admin']) {
			if ($sgids === false) {
				$sgsids = $this->SharingGroup->fetchAllAuthorised($user);
			}
			$conditions = array(
				'AND' => array(
					'OR' => array(
						array(
							'AND' => array(
								'Event.org_id' => $user['org_id'],
							)
						),
						array(
							'AND' => array(
								$this->buildEventConditions($user, $sgids),
								'OR' => array(
									'Object.distribution' => array('1', '2', '3', '5'),
									'AND '=> array(
										'Object.distribution' => 4,
										'Object.sharing_group_id' => $sgsids,
									)
								)
							)
						)
					)
				)
			);
		}
		return $conditions;
	}


	// Method that fetches all objects
	// very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
	// options:
	//     fields
	//     contain
	//     conditions
	//     order
	//     group
	public function fetchObjects($user, $options = array()) {
		$sgsids = $this->SharingGroup->fetchAllAuthorised($user);
		$params = array(
			'conditions' => $this->buildConditions($user),
			'recursive' => -1,
			'contain' => array(
				'Event' => array(
					'fields' => array('id', 'info', 'org_id', 'orgc_id'),
				),
				'Attribute' => array(
					'conditions' => array(
						'OR' => array(
							array(
								'Event.org_id' => $user['org_id'],
							),
							array(
								'OR' => array(
									'Attribute.distribution' => array(1, 2, 3, 5),
									array(
										'Attribute.distribution' => 4,
										'Attribute.sharing_group_id' => $sgids
									)
								)
							)
						)
					),
					'ShadowAttribute',
					'AttributeTag' => array(
						'Tag'
					)
				)
			)
		);
		if (empty($options['includeAllTags'])) $params['contain']['Attribute']['AttributeTag']['Tag']['conditions']['exportable'] = 1;
		if (isset($options['contain'])) $params['contain'] = array_merge_recursive($params['contain'], $options['contain']);
		else $option['contain']['Event']['fields'] = array('id', 'info', 'org_id', 'orgc_id');
		if (Configure::read('MISP.proposals_block_attributes') && isset($options['conditions']['AND']['Attribute.to_ids']) && $options['conditions']['AND']['Attribute.to_ids'] == 1) {
			$this->Attribute->bindModel(array('hasMany' => array('ShadowAttribute' => array('foreignKey' => 'old_id'))));
			$proposalRestriction =  array(
					'ShadowAttribute' => array(
							'conditions' => array(
									'AND' => array(
											'ShadowAttribute.deleted' => 0,
											'OR' => array(
													'ShadowAttribute.proposal_to_delete' => 1,
													'ShadowAttribute.to_ids' => 0
											)
									)
							),
							'fields' => array('ShadowAttribute.id')
					)
			);
			$params['contain'] = array_merge($params['contain']['Attribute'], $proposalRestriction);
		}
		if (isset($options['fields'])) $params['fields'] = $options['fields'];
		if (isset($options['conditions'])) $params['conditions']['AND'][] = $options['conditions'];
		if (isset($options['order'])) $params['order'] = $options['order'];
		if (!isset($options['withAttachments'])) $options['withAttachments'] = false;
		else ($params['order'] = array());
		if (!isset($options['enforceWarninglist'])) $options['enforceWarninglist'] = false;
		if (!$user['Role']['perm_sync'] || !isset($options['deleted']) || !$options['deleted']) $params['contain']['Attribute']['conditions']['AND']['Attribute.deleted'] = 0;
		if (isset($options['group'])) {
			$params['group'] = array_merge(array('Object.id'), $options['group']);
		}
		if (Configure::read('MISP.unpublishedprivate')) $params['conditions']['AND'][] = array('OR' => array('Event.published' => 1, 'Event.orgc_id' => $user['org_id']));
		$results = $this->find('all', $params);
		if ($options['enforceWarninglist']) {
			$this->Warninglist = ClassRegistry::init('Warninglist');
			$warninglists = $this->Warninglist->fetchForEventView();
		}
		$results = array_values($results);
		$proposals_block_attributes = Configure::read('MISP.proposals_block_attributes');
		foreach ($results as $key => $objects) {
			foreach ($objects as $key2 => $attribute) {
				if ($options['enforceWarninglist'] && !$this->Warninglist->filterWarninglistAttributes($warninglists, $attribute['Attribute'], $this->Warninglist)) {
					unset($results[$key][$key2]);
					continue;
				}
				if ($proposals_block_attributes) {
					if (!empty($attribute['ShadowAttribute'])) {
						unset($results[$key][$key2]);
					} else {
						unset($results[$key][$key2]['ShadowAttribute']);
					}
				}
				if ($options['withAttachments']) {
					if ($this->typeIsAttachment($attribute['Attribute']['type'])) {
						$encodedFile = $this->base64EncodeAttachment($attribute['Attribute']);
						$results[$key][$key2]['Attribute']['data'] = $encodedFile;
					}
				}
			}
		}
		return $results;
	}

	/*
	 * Prepare the template form view's data, setting defaults, sorting elements
	 */
	public function prepareTemplate($template, $request = array()) {
		$temp = array();
		usort($template['ObjectTemplateElement'], function($a, $b) {
			return $a['ui-priority'] < $b['ui-priority'];
		});
		$request_rearranged = array();
		$template_object_elements = $template['ObjectTemplateElement'];
		unset($template['ObjectTemplateElement']);
		if (!empty($request['Attribute'])) {
			foreach ($request['Attribute'] as $attribute) {
				$request_rearranged[$attribute['object_relation']][] = $attribute;
			}
		}
		foreach ($template_object_elements as $k => $v) {
			if (empty($request_rearranged[$v['object_relation']])) {
				if (isset($this->Event->Attribute->typeDefinitions[$v['type']])) {
					$v['default_category'] = $this->Event->Attribute->typeDefinitions[$v['type']]['default_category'];
					$v['to_ids'] = $this->Event->Attribute->typeDefinitions[$v['type']]['to_ids'];
					if (empty($v['categories'])) {
						$v['categories'] = array();
						foreach ($this->Event->Attribute->categoryDefinitions as $catk => $catv) {
							if (in_array($v['type'], $catv['types'])) {
								$v['categories'][] = $catk;
							}
						}
					}
					$template['ObjectTemplateElement'][] = $v;
				} else {
					$template['warnings'][] = 'Missing attribute type "' . $v['type'] . '" found. Omitted template element ("' . $template_object_elements[$k]['object_relation'] . '") that would not pass validation due to this.';
				}
			} else {
				foreach($request_rearranged[$v['object_relation']] as $request_item) {
					if (isset($this->Event->Attribute->typeDefinitions[$v['type']])) {
						$v['default_category'] = $request_item['category'];
						$v['value'] = $request_item['value'];
						$v['to_ids'] = $request_item['to_ids'];
						$v['comment'] = $request_item['comment'];
						if (!empty($request_item['uuid'])) $v['uuid'] = $request_item['uuid'];
						if (isset($request_item['data'])) $v['data'] = $request_item['data'];
						if (empty($v['categories'])) {
							$v['categories'] = array();
							foreach ($this->Event->Attribute->categoryDefinitions as $catk => $catv) {
								if (in_array($v['type'], $catv['types'])) {
									$v['categories'][] = $catk;
								}
							}
						}
						$template['ObjectTemplateElement'][] = $v;
					} else {
						$template['warnings'][] = 'Missing attribute type "' . $v['type'] . '" found. Omitted template element ("' . $template_object_elements[$k]['object_relation'] . '") that would not pass validation due to this.';
					}
				}
			}
		}
		return $template;
	}

	/*
	 * Clean the attribute list up from artifacts introduced by the object form
	 */
	public function attributeCleanup($attributes) {
		if (empty($attributes['Attribute'])) return 'No attribute data found';
		foreach ($attributes['Attribute'] as $k => $attribute) {
			if (isset($attribute['save']) && $attribute['save'] == 0) {
				unset($attributes['Attribute'][$k]);
				continue;
			}
			if (isset($attribute['value_select'])) {
				if ($attribute['value_select'] !== 'Enter value manually') {
					$attributes['Attribute'][$k]['value'] = $attribute['value_select'];
				}
				unset($attributes['Attribute'][$k]['value_select']);
			}
			if (isset($attribute['Attachment'])) {
				// Check if there were problems with the file upload
				// only keep the last part of the filename, this should prevent directory attacks
				$filename = basename($attribute['Attachment']['name']);
				$tmpfile = new File($attribute['Attachment']['tmp_name']);
				if ((isset($attribute['Attachment']['error']) && $attribute['Attachment']['error'] == 0) ||
					(!empty($attribute['Attachment']['tmp_name']) && $attribute['Attachment']['tmp_name'] != 'none')
				) {
					if (!is_uploaded_file($tmpfile->path))
						throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
				} else {
					return 'Issues with the file attachment for the ' . $attribute['object_relation'] . ' attribute. The error code returned is ' . $attribute['Attachment']['error'];
				}
				$attributes['Attribute'][$k]['value'] = $attribute['Attachment']['name'];
				unset($attributes['Attribute'][$k]['Attachment']);
				$attributes['Attribute'][$k]['encrypt'] = $attribute['type'] == 'malware-sample' ? 1 : 0;
				$attributes['Attribute'][$k]['data'] = base64_encode($tmpfile->read());
				$tmpfile->delete();
				$tmpfile->close();
			}
			unset($attributes['Attribute'][$k]['save']);
		}
		return $attributes;
	}

	public function deltaMerge($object, $objectToSave) {
		$object['Object']['comment'] = $objectToSave['Object']['comment'];
		$object['Object']['distribution'] = $objectToSave['Object']['distribution'];
		if ($object['Object']['distribution'] == 4) {
			$object['Object']['sharing_group_id'] = $objectToSave['Object']['sharing_group_id'];
		}
		$date = new DateTime();
		$object['Object']['timestamp'] = $date->getTimestamp();
		$this->save($object);
		$checkFields = array('category', 'value', 'to_ids', 'distribution', 'sharing_group_id', 'comment');
		foreach ($objectToSave['Attribute'] as $newKey => $newAttribute) {
			foreach ($object['Attribute'] as $origKey => $originalAttribute) {
				if (!empty($newAttribute['uuid'])) {
					if ($newAttribute['uuid'] == $originalAttribute['uuid']) {
						$different = false;
						foreach ($checkFields as $f) {
							if ($f == 'sharing_group_id' && empty($newAttribute[$f])) {
								$newAttribute[$f] = 0;
							}
							if ($newAttribute[$f] != $originalAttribute[$f]) $different = true;
						}
						if ($different) {
							$newAttribute['id'] = $originalAttribute['id'];
							$newAttribute['event_id'] = $object['Object']['event_id'];
							$newAttribute['object_id'] = $object['Object']['id'];
							$newAttribute['timestamp'] = $date->getTimestamp();
							$result = $this->Event->Attribute->save(array('Attribute' => $newAttribute), array(
								'category',
								'value',
								'to_ids',
								'distribution',
								'sharing_group_id',
								'comment',
								'timestamp',
								'object_id',
								'event_id'
							));
						}
						unset($object['Attribute'][$origKey]);
						continue 2;
					}
				}
			}
			$this->Event->Attribute->create();
			$newAttribute['event_id'] = $object['Object']['event_id'];
			$newAttribute['object_id'] = $object['Object']['id'];
			$this->Event->Attribute->save($newAttribute);
			$attributeArrays['add'][] = $newAttribute;
			unset($objectToSave['Attribute'][$newKey]);
		}
		foreach ($object['Attribute'] as $origKey => $originalAttribute) {
			$originalAttribute['deleted'] = 1;
			$this->Event->Attribute->save($originalAttribute);
		}
		return $this->id;
	}

	public function captureObject($object, $eventId, $user, $log = false) {
		$this->create();
		if (!isset($object['Object'])) {
			$object = array('Object' => $object);
		}
		if (empty($log)) {
			$log = ClassRegistry::init('Log');
		}
		$object['Object']['event_id'] = $eventId;
		if ($this->save($object)) {
			$this->Event->unpublishEvent($eventId);
			$objectId = $this->id;
			$partialFails = array();
			foreach ($object['Object']['Attribute'] as $attribute) {
				$this->Attribute->captureAttribute($attribute, $eventId, $user, $objectId, $log);
			}
			return true;
		} else {
			$log->create();
			$log->save(array(
					'org' => $user['Organisation']['name'],
					'model' => 'Object',
					'model_id' => 0,
					'email' => $user['email'],
					'action' => 'add',
					'user_id' => $user['id'],
					'title' => 'Object dropped due to validation for Event ' . $eventId . ' failed: ' . $object['Object']['name'],
					'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($attribute),
			));
		}
		return 'fail';
	}

	public function editObject($object, $eventId, $user, $log) {
		$object['event_id'] = $eventId;
		if (isset($object['uuid'])) {
			$existingObject = $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('Object.uuid' => $object['uuid'])
			));
			if (empty($existingObject)) {
				return $this->captureObject($object, $eventId, $user, $log);
			} else {
				if ($existingObject['Object']['event_id'] != $eventId) {
					$log->create();
					$log->save(array(
							'org' => $user['Organisation']['name'],
							'model' => 'Object',
							'model_id' => 0,
							'email' => $user['email'],
							'action' => 'edit',
							'user_id' => $user['id'],
							'title' => 'Duplicate UUID found in object',
							'change' => 'An object was blocked from being saved due to a duplicate UUID. The uuid in question is: ' . $object['uuid'] . '. This can also be due to the same object (or an object with the same UUID) existing in a different event)',
					));
					return true;
				}
				if (isset($object['timestamp'])) {
					if ($existingObject['Object']['timestamp'] >= $object['timestamp']) {
						return true;
					}
				} else {
					$date = new DateTime();
					$object['timestamp'] = $date->getTimestamp();
				}
			}
		} else {
			return $this->captureObject($object, $eventId, $user, $log);
		}
		// At this point we have an existingObject that we can edit
		$recoverFields = array(
			'name',
			'meta-category',
			'description',
			'template_uuid',
			'template_version',
			'distribution',
			'sharing_group_id',
			'comment',
			'deleted'
		);
		foreach ($recoverFields as $rF) if (!isset($object[$rF])) $object[$rF] = $existingObject['Object'][$rF];
		$object['id'] = $existingObject['Object']['id'];
		$object['uuid'] = $existingObject['Object']['uuid'];
		$object['event_id'] = $eventId;
		if ($object['distribution'] == 4) {
			$object['sharing_group_id'] = $this->SharingGroup->captureSG($object['SharingGroup'], $user);
		}
		if (!$this->save($object)) {
			$log->create();
			$log->save(array(
				'org' => $user['Organisation']['name'],
				'model' => 'Object',
				'model_id' => 0,
				'email' => $user['email'],
				'action' => 'edit',
				'user_id' => $user['id'],
				'title' => 'Attribute dropped due to validation for Event ' . $eventId . ' failed: ' . $object['name'],
				'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Object: ' . json_encode($attribute),
			));
			return $this->validationErrors;
		} else {
			$this->Event->unpublishEvent($eventId);
		}
		if (!empty($object['Attribute'])) {
			foreach ($object['Attribute'] as $attribute) {
				$result = $this->Attribute->editAttribute($attribute, $eventId, $user, $object['id'], $log);
			}
		}
		return true;
	}

	public function updateTimestamp($id) {
		$date = new DateTime();
		$object = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array('Object.id' => $id)
		));
		$object['Object']['timestamp'] = $date->getTimestamp();
		$object['Object']['skip_zmq'] = 1;
		$result = $this->save($object);
		return $result;
	}

	// Hunt down all LEDA and CASTOR clones
	public function removeOrphanedObjects() {
		$orphans = $this->find('list', array(
			'fields' => array('Object.id', 'Object.id'),
			'conditions' => array('Event.id' => null),
			'contain' => array('Event' => array('fields' => array('id')))
		));
		foreach ($orphans as $orphan) {
			$this->delete($orphan);
		}
		return count($orphans);
	}
}
