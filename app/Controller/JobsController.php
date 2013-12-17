<?php

App::uses('AppController', 'Controller');

/**
 * Jobs Controller
 *
 * @property Job $Job
*/
class JobsController extends AppController {
	public $components = array('Security' ,'RequestHandler', 'Session');
	
	public $paginate = array(
			'limit' => 20,
			'order' => array(
					'Job.id' => 'desc'
			)
	);
	
	public function beforeFilter() {
		parent::beforeFilter();
	}
	
	public function index() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
		if (!Configure::read('MISP.background_jobs')) throw new NotFoundException('Background jobs are not enabled on this instance.');
		$this->recursive = 0;
		$jobs = $this->paginate();
		foreach($jobs as &$job) {
			if ($job['Job']['process_id']) {
				$job['Job']['status'] = $this->__jobStatusConverter(CakeResque::getJobStatus($job['Job']['process_id']));
			} else {
				$job['Job']['status'] = '???';
			}
		}
		$this->set('list', $jobs);
	}
	
	private function __jobStatusConverter($status) {
		switch ($status) {
			case 1:
				return 'In progress...';
				break;
			case 2:
				return 'Unknown';
				break;
			case 3:
				return 'Unknown';
				break;
			case 4:
				return 'Completed';
				break;
		}
	}
	
	public function getGenerateCorrelationProgress($id) {
		//if (!self::_isSiteAdmin()) throw new NotFoundException();
		$progress = $this->Job->findById($id);
		if (!$progress) {
			$progress = 0;
		} else {
			$progress = $progress['Job']['progress'];
		}
		return new CakeResponse(array('body' => json_encode($progress)));
	}
	
	public function getProgress($type) {
		$org = $this->Auth->user('org');
		if ($this->_isSiteAdmin()) $org = 'ADMIN'; 
		$progress = $this->Job->find('first', array(
			'conditions' => array(
				'job_type' => $type,
				'org' => $org
			),
			'fields' => array('id', 'progress'),
			'order' => array('Job.id' => 'desc'),
		));
		if (!$progress) {
			$progress = 0;
		} else {
			$progress = $progress['Job']['progress'];
		}
		return new CakeResponse(array('body' => json_encode($progress)));
	}
	
	public function cache($type) {
		if ($this->_isSiteAdmin()) {
			$target = 'All events.';
			$jobOrg = 'ADMIN';
		} else { 
			$target = 'Events visible to: '.$this->Auth->user('org');
			$jobOrg = $this->Auth->user('org');
		}
		$extra = null;
		$extra2 = null;
		$shell = 'Event';
		$this->Job->create();
		$data = array(
			'worker' => 'cache',
			'job_type' => 'cache_' . $type,
			'job_input' => $target,
			'status' => 0,
			'retries' => 0,
			'org' => $jobOrg,
			'message' => 'Fetching events.',
		);
		if ($type === 'md5' || $type === 'sha1') {
			$extra = $type;
			$type = 'hids';
		}
		if ($type === 'csv_all' || $type === 'csv_sig') {
			$extra = $type;
			$type = 'csv';
		}
		if ($type === 'suricata' || $type === 'snort') {
			$extra = $type;
			$type = 'nids';
			$extra2 = $this->Auth->user('sid');
		}
		$this->Job->save($data);
		$id = $this->Job->id;
		$process_id = CakeResque::enqueue(
			'cache',
			$shell . 'Shell',
			array('cache' . $type, $this->Auth->user('org'), $this->_isSiteAdmin(), $id, $extra, $extra2),
			true
		);
		$this->Job->saveField('process_id', $process_id);
		return new CakeResponse(array('body' => json_encode($id)));
	}
	
	public function jobScheduler() {
		if (!$this->_isSiteAdmin()) throw new MethodNotAllowedException();
	}
	
	public function stopWorker() {
		debug(CakeResque::getFailedJobLog('323c143da4e12cf682554c4a8742f412'));
	}
}
