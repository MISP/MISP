<?php
App::uses('AppModel', 'Model');

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

}
