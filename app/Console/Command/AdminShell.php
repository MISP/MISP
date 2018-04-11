<?php
App::uses('AppShell', 'Console/Command');
class AdminShell extends AppShell
{
	public $uses = array('Event', 'Post', 'Attribute', 'Job', 'User', 'Task', 'Whitelist', 'Server', 'Organisation');

	public function jobGenerateCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Attribute');
		$this->Attribute->generateCorrelation($jobId, 0);
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function jobPurgeCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Attribute');
		$this->Attribute->purgeCorrelations();
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function jobGenerateShadowAttributeCorrelation() {
		$jobId = $this->args[0];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('ShadowAttribute');
		$this->ShadowAttribute->generateCorrelation($jobId);
	}

	public function jobUpgrade24() {
		$jobId = $this->args[0];
		$user_id = $this->args[1];
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Server');
		$this->Server->upgrade2324($user_id, $jobId);
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function prune_update_logs() {
		$jobId = $this->args[0];
		$user_id = $this->args[1];
		$user = $this->User->getAuthUser($user_id);
		$this->loadModel('Job');
		$this->Job->id = $jobId;
		$this->loadModel('Log');
		$this->Log->pruneUpdateLogs($jobId, $user);
		$this->Job->saveField('progress', 100);
		$this->Job->saveField('message', 'Job done.');
		$this->Job->saveField('status', 4);
	}

	public function getSetting() {
		$param = empty($this->args[0]) ? 'all' : $this->args[0];
		$settings = $this->Server->serverSettingsRead();
		$result = $settings;
		if (!empty($param)) {
			$result = 'No valid setting found for ' . $param;
			foreach ($settings as $setting) {
				if ($setting['setting'] == $param) {
					$result = $setting;
					break;
				}
			}
		}
		echo json_encode($result, JSON_PRETTY_PRINT) . PHP_EOL;
	}

	public function setSetting() {
		$setting = !isset($this->args[0]) ? null : $this->args[0];
		$value = !isset($this->args[1]) ? null : $this->args[1];
		if (empty($setting) || $value === null) {
			echo 'Invalid parameters. Usage: ' . APP . 'Console/cake Admin setSetting [setting_name] [setting_value]';
		} else {
			$this->Server->serverSettingsSaveValue($setting, $value);
		}
	}
}
