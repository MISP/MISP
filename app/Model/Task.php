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
	
	// takes a time in the 24h format (13:49) and an integer representing the number of hours 
	// by which it needs to be incremeneted. Returns a string in the first parameters format
	public function breakTime($time, $timeToAdd) {
		$temp = explode(':', $time);
		$hours = $timeToAdd%24;
		$temp[0] = $temp[0] + $hours;
		if ($temp[0] > 23) $temp[0] = $temp[0] - 24;
		return $temp[0] . ':' . $temp[1];
	}
}
