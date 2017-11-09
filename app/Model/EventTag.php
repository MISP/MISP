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
		'Event',
		'Tag'
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

	public function getSortedTagList($context = false) {
		$conditions = array();
		$tag_counts = $this->find('all', array(
				'recursive' => -1,
				'fields' => array('tag_id', 'count(*)'),
				'group' => array('tag_id'),
				'conditions' => $conditions,
				'contain' => array('Tag.name')
		));
		$temp = array();
		$tags = array();
		foreach ($tag_counts as $tag_count) {
			$temp[$tag_count['Tag']['name']] = array(
					'tag_id' => $tag_count['Tag']['id'],
					'eventCount' => $tag_count[0]['count(*)'],
					'name' => $tag_count['Tag']['name'],
			);
			$tags[$tag_count['Tag']['name']] = $tag_count[0]['count(*)'];
		}
		arsort($tags);
		foreach ($tags as $k => $v) {
			$tags[$k] = $temp[$k];
		}
		return $tags;
	}

	public function countForTag($tag_id, $user, $sgids = array()) {
		$db = $this->getDataSource();
		$subQuery = $db->buildStatement(
			array(
				'fields' => array('EventTag.event_id'),
				'table' => 'event_tags',
				'alias' => 'EventTag',
				'limit' => null,
				'offset' => null,
				'joins' => array(),
				'conditions' => array(
					'EventTag.tag_id' => $tag_id
				),
			),
			$this
		);
		$subQuery = 'Event.id IN (' . $subQuery . ') ';
		$conditions = array(
			$db->expression($subQuery)->value
		);
		if (!$user['Role']['perm_site_admin']) {
			$conditions = array_merge(
				$conditions,
				array('OR' => array(
					array('Event.distribution' => array(1, 2, 3)),
					array('Event.orgc_id' => $user['org_id'])
				))
			);
			if (!empty($sgids)) {
				$conditions['OR'][] = array('AND' => array(
					'Event.distribution' => 4,
					'Event.sharing_group_id' => $sgids
				));
			}
		}
		return $this->Event->find('count', array(
			'fields' => array('Event.id', 'Event.distribution', 'Event.orgc_id', 'Event.sharing_group_id'),
			'conditions' => $conditions
		));
	}
}
