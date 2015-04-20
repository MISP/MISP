<?php

App::uses('AppModel', 'Model');

/**
 * Thread Model
 *
*/
class Thread extends AppModel {
	public $actsAs = array(
			'Containable',
			'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
					'roleModel' => 'Thread',
					'roleKey' => 'thread_id',
					'change' => 'full'
			),
	);
	public $hasMany = 'Post';
	public $belongsTo = array(
		'Event', 
		'Organisation' => array(
			'className' => 'Organisation',
			'foreignKey' => 'org_id'
		),
		'SharingGroup'
	);
	
	public function updateAfterPostChange($add = false) {
		$count = count($this->data['Post']);
		// If we have 0 posts left, delete the thread!
		if ($count == 0) {
			$this->delete();
			return false;
		} else {
			$this->data['Thread']['post_count'] = $count;
			if ($add) {
				$this->data['Thread']['date_modified'] = date('Y/m/d h:i:s');
			}
			$this->save($this->data);
			return true;
		}
	}
}
