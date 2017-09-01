<?php

App::uses('AppController', 'Controller');

class JobsController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');

	public $paginate = array(
			'limit' => 20,
			'order' => array(
					'Job.id' => 'desc'
			),
	);

	public function index($queue = false) {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if (!Configure::read('MISP.background_jobs')) throw new NotFoundException('Background jobs are not enabled on this instance.');
		$this->loadModel('Server');
		$issueCount = 0;
		$workers = $this->Server->workerDiagnostics($issueCount);
		$this->recursive = 0;
		$queues = array('email', 'default', 'cache', 'prio');
		if ($queue && in_array($queue, $queues)) $this->paginate['conditions'] = array('Job.worker' => $queue);
		$jobs = $this->paginate();
		foreach ($jobs as &$job) {
			if ($job['Job']['process_id'] !== false) {
				$job['Job']['job_status'] = $this->__jobStatusConverter(CakeResque::getJobStatus($job['Job']['process_id']));
				$job['Job']['failed'] = false;
				if ($job['Job']['status'] === 'Failed') {
					$job['Job']['failed'] = true;
				}
			} else {
				$job['Job']['status'] = 'Unknown';
			}
			$job['Job']['worker_status'] = isset($workers[$job['Job']['worker']]) && $workers[$job['Job']['worker']]['ok'] ? true : false;
		}
		$this->set('list', $jobs);
		$this->set('queue', $queue);
	}

	public function getError($id) {
		$fields = array(
			'Failed at' => 'failed_at',
			'Exception' => 'exception',
			'Error' => 'error'
		);
		$this->set('fields', $fields);
		$this->set('response', CakeResque::getFailedJobLog($id));
		$this->render('/Jobs/ajax/error');
	}

	private function __jobStatusConverter($status) {
		switch ($status) {
			case 1:
				return 'Waiting';
				break;
			case 2:
				return 'Running';
				break;
			case 3:
				return 'Failed';
				break;
			case 4:
				return 'Completed';
				break;
			default:
				return 'Unknown';
				break;
		}
	}

	public function getGenerateCorrelationProgress($id) {
		if (!self::_isSiteAdmin()) throw new NotFoundException();
		$progress = $this->Job->findById($id);
		if (!$progress) {
			$progress = 0;
		} else {
			$progress = $progress['Job']['progress'];
		}
		return new CakeResponse(array('body' => json_encode($progress), 'type' => 'json'));
	}

	public function getProgress($type) {
		$org_id = $this->Auth->user('org_id');
		if ($this->_isSiteAdmin()) $org_id = 0;

		if (is_numeric($type)) {
			$progress = $this->Job->find('first', array(
				'conditions' => array(
					'Job.id' => $type,
					'org_id' => $org_id
				),
				'fields' => array('id', 'progress'),
				'order' => array('Job.id' => 'desc'),
			));
		} else {
			$progress = $this->Job->find('first', array(
				'conditions' => array(
					'job_type' => $type,
					'org_id' => $org_id
				),
				'fields' => array('id', 'progress'),
				'order' => array('Job.id' => 'desc'),
			));
		}
		if (!$progress) {
			$progress = 0;
		} else {
			$progress = $progress['Job']['progress'];
		}
		if ($this->_isRest()) {
			return $this->RestResponse->viewData(array('progress' => $progress . '%'), $this->response->type());
		} else {
			return new CakeResponse(array('body' => json_encode($progress), 'type' => 'json'));
		}
	}

	public function cache($type) {
		if (Configure::read('MISP.disable_cached_exports')) {
			throw new MethodNotAllowedException('This feature is currently disabled');
		}
		if ($this->_isSiteAdmin()) {
			$target = 'All events.';
		} else {
			$target = 'Events visible to: '.$this->Auth->user('Organisation')['name'];
		}
		$id = $this->Job->cache($type, $this->Auth->user());
		if ($this->_isRest()) {
			return $this->RestResponse->viewData(array('job_id' => $id), $this->response->type());
		} else {
			return new CakeResponse(array('body' => json_encode($id), 'type' => 'json'));
		}
	}
}
