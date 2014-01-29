<?php

App::uses('AppController', 'Controller');

/**
 * Tasks Controller
 *
 * @property Task $Task
*/
class TasksController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');
	
	public $paginate = array(
			'limit' => 20,
			'order' => array(
					'Task.id' => 'desc'
			)
	);
	
	public function beforeFilter() {
		parent::beforeFilter();
	}
	
	public function index() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if (!Configure::read('MISP.background_jobs')) throw new NotFoundException('Background jobs are not enabled on this instance.');
		$this->__checkTasks();
		$this->recursive = 0;
		$tasks = $this->paginate();
		$this->set('list', $tasks);
		$this->set('time', time());
	}
	
	// checks if all the mandatory tasks exist, and if not, creates them
	// default tasks are: 
	// 'cache_exports'
	private function __checkTasks() {
		foreach ($this->Task->tasks as $default_task) {
			if (!$this->Task->findByType($default_task['type'], array('id', 'type'))) {
				$this->Task->save($default_task);
			}
		}
	}
	
	public function setTask() {
		if (!$this->_isSiteAdmin()) {
			throw new MethodNotAllowedException('You are not authorised to do that.');
		}
		$today = $this->_getTodaysTimestamp();
		if ($this->request->is('post') || $this->request->is('put')) {
			$tasks = $this->Task->find('all', array('fields' => array('id', 'timer', 'scheduled_time', 'type', 'next_execution_time')));
			foreach ($tasks as $k => $task) {
				if ($this->request->data['Task'][$task['Task']['id']]['timer'] !== $task['Task']['timer'] ||
				$this->request->data['Task'][$task['Task']['id']]['scheduled_time'] !== $task['Task']['scheduled_time'] ||
				$this->request->data['Task'][$task['Task']['id']]['next_execution_time'] !== date("Y-m-d", $task['Task']['next_execution_time'])) {
					$this->request->data['Task'][$task['Task']['id']]['id'] = $task['Task']['id'];
					if (isset($this->request->data['Task'][$task['Task']['id']]['next_execution_time'])) {
						$temp = $this->request->data['Task'][$task['Task']['id']]['next_execution_time'];
					} else {
						$temp = date("Y-m-d", $task['Task']['next_execution_time']);
					}
					if (isset($this->request->data['Task'][$task['Task']['id']]['scheduled_time'])) {
						$this->request->data['Task'][$task['Task']['id']]['next_execution_time'] = strtotime($temp . ' ' . $this->request->data['Task'][$task['Task']['id']]['scheduled_time']);
					} else {
						$this->request->data['Task'][$task['Task']['id']]['next_execution_time'] = strtotime($temp . ' ' . $task['Task']['scheduled_time']);
					}
					// schedule task
					$this->_jobScheduler($task['Task']['type'], $this->request->data['Task'][$task['Task']['id']]['next_execution_time'], $task['Task']['id']);
					$this->Task->save($this->request->data['Task'][$task['Task']['id']]);
				}
			}
			$this->Session->setFlash('Task edited');
			$this->redirect(array('action' => 'index'));
		}
	}
	
	private function _getTodaysTimestamp() {
		return strtotime(date("d/m/Y") . ' 00:00:00');
	}
	
	private function _jobScheduler($type, $timestamp, $id) {
		if ($type === 'cache_exports') $this->_cacheScheduler($timestamp, $id);
		if ($type === 'pull_all') $this->_pullScheduler($timestamp, $id);
		if ($type === 'push_all') $this->_pushScheduler($timestamp, $id);
	}
	
	private function _cacheScheduler($timestamp, $id) {
		CakeResque::enqueueAt(
				$timestamp,
				'cache',
				'EventShell',
				array('enqueueCaching', $timestamp),
				true
		);
	}

	private function _pushScheduler($timestamp, $id) {
		$process_id = CakeResque::enqueueAt(
				$timestamp,
				'default',
				'ServerShell',
				array('enqueuePush', $timestamp, $id, $this->Auth->user('org')),
				true
		);
		$this->Task->id = $id;
		$this->Task->saveField('job_id', $process_id);
	}
	
	private function _pullScheduler($timestamp, $id) {
		$process_id = CakeResque::enqueueAt(
				$timestamp,
				'default',
				'ServerShell',
				array('enqueuePull', $timestamp, $this->Auth->user('id'),  $id),
				true
		);
		$this->Task->id = $id;
		$this->Task->saveField('job_id', $process_id);
	}

}
