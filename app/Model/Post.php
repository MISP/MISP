<?php

App::uses('AppModel', 'Model');

/**
 * Post Model
 *
*/
class Post extends AppModel {
	public $actsAs = array('Containable');
	
	public $belongsTo = array(
			'Thread',
			'User' => array(
				'fields' => array('email', 'org', 'id'),
					
			)
	);
}
