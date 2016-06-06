<?php
App::uses('AppModel', 'Model');

class EventTag extends AppModel {

	public $actsAs = array('Containable');

	public $validate = array(
		'event_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'tag_id' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
	);

	public $belongsTo = array(
		'Event' => array(
			'className' => 'Event',
		),
		'Tag' => array(
			'className' => 'Tag',
		),
	);

	// take an array of tag names to be included and an array with tagnames to be excluded and find all event IDs that fit the criteria
	public function getEventIDsFromTags($includedTags, $excludedTags) {
		$conditions = array();
		if (!empty($includedTags)) $conditions['OR'] = array('name' => $includedTags);
		if (!empty($excludedTags)) $conditions['NOT'] = array('name' => $excludedTags);
		$tags = $this->Tag->find('all', array(
			'recursive' => -1,
			'fields' => array('id', 'name'),
			'conditions' => $conditions
		));
		$tagIDs = array();
		foreach ($tags as $tag) {
			$tagIDs[] = $tag['Tag']['id'];
		}
		$eventTags = $this->find('all', array(
			'recursive' => -1,
			'conditions' => array('tag_id' => $tagIDs)
		));
		$eventIDs = array();
		foreach ($eventTags as $eventTag) {
			$eventIDs[] = $eventTag['EventTag']['event_id'];
		}
		$eventIDs = array_unique($eventIDs);
		return $eventIDs;
	}

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
}
