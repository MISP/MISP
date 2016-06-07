<?php
App::uses('AppModel', 'Model');

class EventDelegation extends AppModel {

	public $actsAs = array('Containable');

	public $validate = array(
		'event_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'org_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		)
	);

	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
		),
		'Org' => array(
			'className' => 'Organisation',
		),
		'RequesterOrg' => array(
			'className' => 'Organisation'
		),
		'SharingGroup' => array(
			'className' => 'SharingGroup'
		)
	);

	public function attachTagToEvent($event_id, $tag_id) {
		$existingAssociation = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array(
				'tag_id' => $tag_id,
				'event_id' => $event_id
			)
		));
		if (empty($existingAssociation)) {
			$this->create();
			if (!$this->save(array('event_id' => $event_id, 'tag_id' => $tag_id))) return false;
		}
		return true;
	}

	public function transferEvent($delegation, $user) {
		$this->Event->Attribute->bindModel(
			array(
				'hasMany' => array(
					'ShadowAttribute' => array(
							'className' => 'ShadowAttribute',
							'foreignKey' => 'old_id'
					)
				)
			)
		);
		$event = $this->Event->find('first', array(
				'conditions' => array('Event.id' => $delegation['EventDelegation']['event_id']),
				'recursive' => -1,
				'contain' => array(
						'ShadowAttribute' => array(
							'conditions' => array(
								'ShadowAttribute.old_id' => 0,
								'ShadowAttribute.event_id' => $delegation['EventDelegation']['event_id']
							)
						),
						'EventTag',
						'Attribute' => array(
							'ShadowAttribute'
						)
				),
		));
		$event['Event']['user_id'] = $user['id'];
		$event['Event']['orgc_id'] = $delegation['EventDelegation']['org_id'];
		$event['Event']['org_id'] = $delegation['EventDelegation']['org_id'];
		$this->Event->delete($delegation['EventDelegation']['event_id']);
		$event_id = $this->Event->savePreparedEvent($event);
		return $event_id;
	}

	private function __prepareEvent(&$event) {
		$objects = array('Attribute', 'ShadowAttribute', 'EventTag');
		$objects = array(
				'Attribute' => array('id', 'event_id'),
				'EventTag' => array('id', 'event_id'),
				'ShadowAttribute' => array('id', 'event_id'),
		);
		$objectsWithAttachments = array('Attribute', 'ShadowAttribute');
		$objectsToRearrange = array('Attribute', 'ShadowAttribute', 'EventTag');
		unset($event['Event']['id']);
		foreach ($objects as $object_type => $fields) {
			foreach ($event[$object_type] as &$object) {
				// append attachment
				if (in_array($object_type, $objectsWithAttachments)) {
					if ($this->Event->Attribute->typeIsAttachment($object['type'])) {
						$encodedFile = $this->Event->$object_type->base64EncodeAttachment($object);
						$object['data'] = $encodedFile;
					}
				}

				// unset ID fields and relations
				foreach ($fields as $field) {
					unset($object[$field]);
				}
			}
			if (in_array($object_type, $objectsToRearrange)) {
				$event['Event'][$object_type] = $event[$object_type];
				unset($event[$object_type]);
			}
		}
	}
}
