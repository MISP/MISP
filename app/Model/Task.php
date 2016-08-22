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
					'scheduled_time' => '12:00',
					'job_id' => 0,
					'description' => 'Generates export caches for every export type and for every organisation. This process is heavy, schedule so it might be a good idea to schedule this outside of working hours and before your daily automatic imports on connected services are scheduled.',
					'next_execution_time' => 1391601600,
					'message' => 'Not scheduled yet.'

			),
			'pull_all' => array(
					'type' => 'pull_all',
					'timer' => 0,
					'scheduled_time' => '12:00',
					'job_id' => 0,
					'description' => 'Initiates a full pull for all eligible instances.',
					'next_execution_time' => 1391601600,
					'message' => 'Not scheduled yet.'

			),
			'push_all' => array(
					'type' => 'push_all',
					'timer' => 0,
					'scheduled_time' => '12:00',
					'job_id' => 0,
					'description' => 'Initiates a full push for all eligible instances.',
					'next_execution_time' => 1391601600,
					'message' => 'Not scheduled yet.'
			)
	);

	// takes a time in the 24h format (13:49) and an integer representing the number of hours
	// by which it needs to be incremeneted. Returns a string in the first parameters format
	public function breakTime($time, $timeToAdd) {
		$temp = explode(':', $time);
		$hours = $timeToAdd%24;
		$temp[0] = $temp[0] + $hours;
		if ($temp[0] > 23) $temp[0] = $temp[0] - 24;
		return $temp[0] . ':' . $temp[1];
	}

	public function reQueue($task, $worker, $shell, $action, $userId, $taskId) {
		$time = time();
		// Keep adding the timer's time interval until we get a date that is in the future! We don't want to keep queuing tasks in the past since they will execute until it catches up.
		while ($task['Task']['next_execution_time'] < $time) {
			$task['Task']['next_execution_time'] = strtotime('+' . $task['Task']['timer'] . ' hours', $task['Task']['next_execution_time']);
		}
		$task['Task']['scheduled_time'] = $this->breakTime($task['Task']['scheduled_time'], $task['Task']['timer']);
		$task['Task']['scheduled_time'] = date('H:i', $task['Task']['next_execution_time']);

		// Now that we have figured out when the next execution should happen, it's time to enqueue it.
		$process_id = CakeResque::enqueueAt(
				$task['Task']['next_execution_time'],
				$worker,
				$shell,
				array($action, $task['Task']['next_execution_time'],$userId, $taskId),
				true
		);
		$task['Task']['job_id'] = $process_id;
		$this->id = $task['Task']['id'];
		$this->save($task);
	}
}
