<?php
App::uses('AppModel', 'Model');
App::uses('Sanitize', 'Utility');

/**
 * Bruteforce Model
 *
 */
class Bruteforce extends AppModel {

	public function insert($ip, $username) {
		$expire = Configure::read('SecureAuth.expire');
		// sanitize fields
		$ip = Sanitize::clean($ip);
		$username = Sanitize::clean($username);
		$this->query("INSERT INTO `bruteforces` (`ip` , `username` , `expire` ) VALUES ('$ip', '$username', TIMESTAMPADD(SECOND,$expire, NOW()));");
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
		$this->query("DELETE FROM `bruteforces` WHERE `expire`<=NOW();");
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
