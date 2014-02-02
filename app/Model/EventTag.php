<?php
App::uses('AppModel', 'Model');

class EventTag extends AppModel {

	public $actsAs = array('Containable');
	
	public $validate = array(
		'event_id' => array(
			'notEmpty' => array(
				'rule' => array('notEmpty'),
				'required' => true
			),
		),
		'tag_id' => array(
			'notEmpty' => array(
				'rule' => array('notEmpty'),
				'required' => true
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
}