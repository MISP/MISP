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
		'Event',
		'Org' => array(
			'className' => 'Organisation',
		),
		'RequesterOrg' => array(
			'className' => 'Organisation'
		),
		'SharingGroup'
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
}
