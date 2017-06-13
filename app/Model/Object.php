<?php

App::uses('AppModel', 'Model');

class Object extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(
					'roleModel' => 'Object',
					'roleKey' => 'object_id',
					'change' => 'full'
			),
	);

	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
			'foreignKey' => 'event_id'
		),
		'SharingGroup' => array(
				'className' => 'SharingGroup',
				'foreignKey' => 'sharing_group_id'
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
		),
	);

	public $validate = array(
	);

	public function saveObject($object, $eventId, $errorBehaviour = 'drop') {
		$this->Object->create();
		$this->request->data['Object']['event_id'] = $eventId;
		$this->Object->save($this->request->data);
		return $this->Object->Attribute->saveAttributes($attributes, $eventId, $objectId = 0, $errorBehaviour);
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
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
					),
				),
				array(
					'AND' => array(
						'Event.sharing_group_id' => $sgids,
						'Event.distribution' => 4,
						Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
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
}
