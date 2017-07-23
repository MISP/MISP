<?php

namespace Model;

class AttributeTag extends AppModel {

	public $actsAs = array('Containable');

	public $validate = array(
		'attribute_id' => array(
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
		'Attribute' => array(
			'className' => 'Attribute',
		),
		'Tag' => array(
			'className' => 'Tag',
		),
	);

	public function attachTagToAttribute($attribute_id, $event_id, $tag_id) {
		$existingAssociation = $this->find('first', array(
			'recursive' => -1,
			'conditions' => array(
				'tag_id' => $tag_id,
				'attribute_id' => $attribute_id
			)
		));
		if (empty($existingAssociation)) {
			$this->create();
			if (!$this->save(array('attribute_id' => $attribute_id, 'event_id' => $event_id, 'tag_id' => $tag_id))) return false;
		}
		return true;
	}

}
