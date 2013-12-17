<?php

App::uses('AppController', 'Controller');

/**
 * Jobs Controller
 *
 * @property Job $Job
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
	
	public function setTask($id) {
		
	}
	
}
