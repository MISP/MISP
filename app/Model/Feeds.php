<?php
App::uses('AppModel', 'Model');
/**
 * Feed Model
 *
 */
class Feed extends AppModel {

	public $name = 'Feed';

	public $actsAs = array('SysLogLogable.SysLogLogable' => array(
			'change' => 'full'
		), 
		'Trim',
		'Containable'
	);
	
	public $belongsTo = array(
	);
	
	public $hasMany = array(
	);

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'url' => array( // TODO add extra validation to refuse multiple time the same url from the same org
			'rule' => array('url'),
			'message' => 'Please enter a valid url.',
		),
		'provider' => array(
			'valueNotEmpty' => array(
				'rule' => array('valueNotEmpty'),
			),
		),
		'name' => array(
				'valueNotEmpty' => array(
						'rule' => array('valueNotEmpty'),
				),
		),
	);
	
	// gets the event UUIDs from the feed by ID
	// returns an array with the UUIDs of events that are new or that need updating
	public function getNewEventUuids($feedId) {
		
	}
	
	public function downloadEvent($feedId, $eventId) {
		
	}
	
}
