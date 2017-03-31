<?php
class PubSubTool {

	private function __getSetSettings() {
		$settings = array(
				'redis_host' => 'localhost',
				'redis_port' => '6379',
				'redis_password' => '',
				'redis_database' => '1',
				'redis_namespace' => 'mispq',
				'port' => '50000',
		);
		foreach ($settings as $key => $setting) {
			$temp = Configure::read('Plugin.ZeroMQ_' . $key);
			if ($temp) $settings[$key] = $temp;
		}
		$settingsFile = new File(APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'settings.json', true, 0644);
		$settingsFile->write(json_encode($settings, true));
		$settingsFile->close();
		return $settings;
	}

	// read the pid file, if it exists, check if the process is actually running
	// if either the pid file doesn't exists or the process is not running return false
	// otherwise return the pid
	public function checkIfRunning() {
		$pidFile = new File(APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.pid');
		$pid = $pidFile->read(true, 'r');
		if ($pid === false || $pid === '') return false;
		if (!is_numeric($pid)) throw new Exception('Internal error (invalid PID file for the MISP zmq script)');
		$result = trim(shell_exec('ps aux | awk \'{print $2}\' | grep ' . $pid));
		if (empty($result)) return false;
		return $pid;
	}

	public function statusCheck() {
		$redis = new Redis();
		$settings = $this->__getSetSettings();
		$redis->connect($settings['redis_host'], $settings['redis_port']);
		$redis->select($settings['redis_database']);
		$redis->rPush($settings['redis_namespace'] . ':command', 'status');
		sleep(1);
		$response = trim($redis->lPop($settings['redis_namespace'] . ':status'));
		return json_decode($response, true);
	}

	public function checkIfPythonLibInstalled() {
		$result = trim(shell_exec('python ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmqtest.py'));
		if ($result === "OK") return true;
		return false;
	}

	private function __setupPubServer() {
		App::uses('File', 'Utility');
		$settings = $this->__getSetSettings();
		if ($this->checkIfRunning() === false) {
			shell_exec('python ' . APP . 'files' . DS . 'scripts' . DS . 'mispzmq' . DS . 'mispzmq.py > ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.log 2> ' . APP . 'tmp' . DS . 'logs' . DS . 'mispzmq.error.log &');
		}
		return $settings;
	}

	public function publishEvent($event) {
		$settings = $this->__setupPubServer();
		App::uses('JSONConverterTool', 'Tools');
		$jsonTool = new JSONConverterTool();
		$json = $jsonTool->convert($event);
		$redis = new Redis();
		$redis->connect($settings['redis_host'], $settings['redis_port']);
		$redis->select($settings['redis_database']);
		$redis->rPush($settings['redis_namespace'] . ':misp_json', $json);
		return true;
	}

	public function killService($settings = false) {
		$redis = new Redis();
		if ($this->checkIfRunning()) {
			if ($settings == false) $settings = $this->__getSetSettings();
			$redis->connect($settings['redis_host'], $settings['redis_port']);
			$redis->select($settings['redis_database']);
			$redis->rPush($settings['redis_namespace'] . ':command', 'kill');
			sleep(1);
			if ($this->checkIfRunning()) return false;
		}
		return true;
	}

	// reload the server if it is running, if not, start it
	public function reloadServer() {
		if (!$this->checkIfRunning()) {
			$settings = $this->__setupPubServer();
		} else {
			$settings = $this->__getSetSettings();
			$redis = new Redis();
			$redis->connect($settings['redis_host'], $settings['redis_port']);
			$redis->select($settings['redis_database']);
			$redis->rPush($settings['redis_namespace'] . ':command', 'reload');
		}
		if (!$this->checkIfRunning()) return 'Setting saved, but something is wrong with the ZeroMQ server. Please check the diagnostics page for more information.';
		return true;
	}

	public function restartServer() {
		if (!$this->killService()) {
			return 'Could not kill the previous instance of the ZeroMQ script.';
		}
		$this->__setupPubServer();
		if (!is_numeric($this->checkIfRunning())) return 'Failed starting the ZeroMQ script.';
		return true;
	}
}
