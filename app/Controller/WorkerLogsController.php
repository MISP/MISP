<?php

App::uses('AppController', 'Controller');

/**
 * WorkerLogs Controller
 *
 * @property WorkerLog $WorkerLog
*/
class WorkerLogsController extends AppController {
	public function beforeFilter() {
		parent::beforeFilter();
	}

	public function index() {
		$this->recursive = 0;
		$this->set('list', $this->paginate());
	}

	public function add() {
		
	}
}
