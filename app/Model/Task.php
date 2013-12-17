<?php
App::uses('AppModel', 'Model');
/**
 * Task Model
 *
 * @property Task $Task
*/
class Task extends AppModel {
	public $tasks = array(
		'cache_exports' => array(
			'type' => 'cache_exports',
			'timer' => 0,
			'scheduled_time' => 0, 
			'recurring' => false,
			'description' => 'Generates export caches for every export type and for every organisation. This process is heavy, schedule so it might be a good idea to schedule this outside of working hours and before your daily automatic imports on connected services are scheduled.'
	));
}
