<?php

App::uses('AppModel', 'Model');

/**
 * Tag Model
 *
 */
class Tag extends AppModel {

/**
 * Use table
 *
 * @var mixed False or table name
 */
	public $useTable = 'tags';

/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'name';
	public $actsAs = array(
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Tag',
					'roleKey' => 'tag_id',
					'change' => 'full'
			),
			'Containable'
	);

	public $validate = array(
			'name' => array(
					'valueNotEmpty' => array(
						'rule' => array('valueNotEmpty'),
					),
					'unique' => array(
							'rule' => 'isUnique',
							'message' => 'A similar name already exists.',
					),
			),
			'colour' => array(
					'valueNotEmpty' => array(
						'rule' => array('valueNotEmpty'),
					),
					'userdefined' => array(
							'rule' => 'validateColour',
							'message' => 'Colour has to be in the RGB format (#FFFFFF)',
					),
			),
	);

	public $hasMany = array(
		'EventTag' => array(
			'className' => 'EventTag',
		),
		'TemplateTag',
		'FavouriteTag' => array(
			'dependent' => true
		)
	);


	public function beforeDelete($cascade = true) {
		$this->EventTag->deleteAll(array('EventTag.tag_id' => $this->id));
	}

	public function validateColour($fields) {
		if (!preg_match('/^#[0-9a-f]{6}$/i', $fields['colour'])) return false;
		return true;
	}

	// find all of the event Ids that belong to the accepted tags and the rejected tags
	public function fetchEventTagIds($accept=array(), $reject=array()) {
		$acceptIds = array();
		$rejectIds = array();
		if (!empty($accept)) {
			$acceptIds = $this->findTags($accept);
			if (empty($acceptIds)) $acceptIds[] = -1;
		}
		if (!empty($reject)) {
			$rejectIds = $this->findTags($reject);
		}
		return array($acceptIds, $rejectIds);
	}

	// find all of the event Ids that belong to tags with certain names
	public function findTags($array) {
		$ids = array();
		foreach ($array as $a) {
			$conditions['OR'][] = array('LOWER(name) like' => '%' . strtolower($a) . '%');
		}
		$params = array(
				'recursive' => 1,
				'contain' => 'EventTag',
				//'fields' => array('id', 'name'),
				'conditions' => $conditions
		);
		$result = $this->find('all', $params);
		foreach ($result as $tag) {
			foreach ($tag['EventTag'] as $eventTag) {
				$ids[] = $eventTag['event_id'];
			}
		}
		return $ids;
	}

	public function captureTag($tag, $user) {
		$existingTag = $this->find('first', array(
				'recursive' => -1,
				'conditions' => array('LOWER(name)' => strtolower($tag['name']))
		));
		if (empty($existingTag)) {
			if ($user['Role']['perm_tag_editor']) {
				$this->create();
				$tag = array(
						'name' => $tag['name'],
						'colour' => $tag['colour'],
						'exportable' => $tag['exportable'],
				);
				$this->save($tag);
				return $this->id;
			} else return false;
		}
		return $existingTag['Tag']['id'];
	}

	// find all tags that belong to a given eventId
	public function findEventTags($eventId) {
		$tags = array();
		$params = array(
				'recursive' => 1,
				'contain' => 'EventTag',
		);
		$result = $this->find('all', $params);
		foreach ($result as $tag) {
			foreach ($tag['EventTag'] as $eventTag) {
				if ($eventTag['event_id'] == $eventId) {
					$tags[] = $tag['Tag'];
				}
			}
		}
		return $tags;
	}

	public function random_color() {
		$colour = '#';
		for ($i = 0; $i < 3; $i++) $colour .= str_pad(dechex(mt_rand(0,255)), 2, '0', STR_PAD_LEFT);
		return $colour;
	}

	public function quickAdd($name, $colour = false) {
		$this->create();
		if ($colour === false) $colour = $this->random_color();
		$data = array(
			'name' => $name,
			'colour' => $colour,
			'exportable' => 1
		);
		return ($this->save($data));
	}

	public function quickEdit($tag, $name, $colour) {
		if ($tag['Tag']['colour'] !== $colour || $tag['Tag']['name'] !== $name) {
			$tag['Tag']['name'] = $name;
			$tag['Tag']['colour'] = $colour;
			return ($this->save($tag['Tag']));
		}
		return true;
	}

	public function getTagsForNamespace($namespace) {
		$tags_temp = $this->find('all', array(
				'recursive' => -1,
				'contain' => 'EventTag',
				'conditions' => array('UPPER(name) LIKE' => strtoupper($namespace) . '%'),
		));
		$tags = array();
		foreach ($tags_temp as &$temp) $tags[strtoupper($temp['Tag']['name'])] = $temp;
		return $tags;
	}
}
