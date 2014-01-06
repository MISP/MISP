<?php
App::uses('AppModel', 'Model');
/**
 * Job Model
 *
 * @property Job $Job
*/
class Job extends AppModel {
	
	public function cache($type, $isSiteAdmin, $org, $target, $jobOrg, $sid) {
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
			$extra2 = $sid;
		}
		$this->save($data);
		$id = $this->id;
		$process_id = CakeResque::enqueue(
				'cache',
				$shell . 'Shell',
				array('cache' . $type, $org, $isSiteAdmin, $id, $extra, $extra2),
				true
		);
		$this->saveField('process_id', $process_id);
		return $id;
	}
}