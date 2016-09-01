<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class Bruteforce extends AppModel {

	public function insert($ip, $username) {
		$expire = time() + Configure::read('SecureAuth.expire');
		$dataSourceConfig = ConnectionManager::getDataSource('default')->config;
		$dataSource = $dataSourceConfig['datasource'];
		// sanitize fields
		$ip = Sanitize::clean($ip);
		$username = Sanitize::clean($username);
		if ($dataSource == 'Database/Mysql') {
			$sql = "INSERT INTO bruteforces (ip, username, `expire`) VALUES ('$ip', '$username', '$expire');";
		} else if ($dataSource == 'Database/Postgres') {
			$sql = "INSERT INTO bruteforces (ip, username, expire) VALUES ('$ip', '$username', '$expire');";
		}
		$this->query($sql);
		if ($this->isBlacklisted($ip, $username)) {
			$this->Log = ClassRegistry::init('Log');
			$this->Log->create();
			$this->Log->save(array(
				'org' => 'SYSTEM',
				'model' => 'Blacklist',
				'model_id' => 0,
				'email' => $username,
				'action' => 'blacklist',
				'title' => 'User from ' . $ip . ' claiming to be ' . $username . ' has been blacklisted after ' . Configure::read('SecureAuth.amount') . ' failed attempts'
			));
		}
	}

	public function clean() {
		$dataSourceConfig = ConnectionManager::getDataSource('default')->config;
		$dataSource = $dataSourceConfig['datasource'];
		if ($dataSource == 'Database/Mysql') {
			$sql = 'DELETE FROM bruteforces WHERE `expire` <= NOW();';
		} else if ($dataSource == 'Database/Postgres') {
			$sql = 'DELETE FROM bruteforces WHERE expire <= NOW();';
		}
		$this->query($sql);
	}

	public function isBlacklisted($ip,$username) {
		// first remove old expired rows
		$this->clean();
		// count
		$params = array('conditions' => array(
						'Bruteforce.ip' => $ip,
						'Bruteforce.username' => $username),);
		$count = $this->find('count', $params);
		if ($count >= Configure::read('SecureAuth.amount')) return true;
		else return false;
	}
}
