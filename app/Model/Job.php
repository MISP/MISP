<?php
App::uses('AppModel', 'Model');
/**
 * Job Model
 *
 * @property Job $Job
*/
class Job extends AppModel {

	public $belongsTo = array(
			'Org' => array(
					'className' => 'Organisation',
					'foreignKey' => 'org_id',
					'order' => array(),
					'fields' => array('id', 'name', 'uuid')
			),
		);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		$date = date('Y-m-d H:i:s');
		if (empty($this->data['Job']['id'])) {
			$this->data['Job']['date_created'] = $date;
			$this->data['Job']['date_modified'] = $date;
		} else {
			$this->data['Job']['date_modified'] = $date;
		}
	}

	public function cache($type, $user, $target, $jobOrg = null) {
		$extra = null;
		$extra2 = null;
		$shell = 'Event';
		$this->create();
		$data = array(
				'worker' => 'cache',
				'job_type' => 'cache_' . $type,
				'job_input' => $target,
				'status' => 0,
				'retries' => 0,
				'org_id' => $user['org_id'],
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
			$extra2 = isset($user['nids_sid']) ? $user['nids_sid'] : 0;
		}
		if ($type === 'rpz') $extra = $type;
		$this->save($data);
		$id = $this->id;
		$process_id = CakeResque::enqueue(
				'cache',
				$shell . 'Shell',
				array('cache' . $type, $user['id'], $id, $extra, $extra2),
				true
		);
		$this->saveField('process_id', $process_id);
		return $id;
	}
}
