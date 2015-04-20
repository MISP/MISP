<?php

App::uses('AppModel', 'Model');

/**
 * Post Model
 *
*/
class Post extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Post',
					'roleKey' => 'post_id',
					'change' => 'full'
			),
	);
	
	public $belongsTo = array(
			'Thread',
			'User'
	);
}
