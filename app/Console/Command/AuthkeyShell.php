<?php
/*
 * Reset a password
 *
 * arg0 = email
 * arg1 = new password
 */
class AuthkeyShell extends AppShell {

	public $uses = array('User', 'Log');

	public function main() {
		if (!isset($this->args[0]) || empty($this->args[0])) echo 'MISP authkey reset command line tool.' . PHP_EOL . 'To assign a new authkey for a user:' . PHP_EOL . APP . 'Console/cake Authkey [email]' . PHP_EOL;
		else {
			// get the users that need their password hashed
			$user = $this->User->find('first', array('conditions' => array('email' => $this->args[0]), 'recursive' => -1, 'contain' => 'Organisation'));
			if (empty($user)) {
				echo 'User not found. Make sure you use the correct syntax: /var/www/MISP/app/Console/cake Authkey [email]' . PHP_EOL;
				exit;
			}
			$this->User->id = $user['User']['id'];
			$newkey = $this->User->generateAuthKey();
			if ($this->User->saveField('authkey', $newkey)) {
				$this->Log->create();
				$this->Log->save(array(
					'org' => $user['Organisation']['name'],
					'model' => 'User',
					'model_id' => $user['User']['id'],
					'email' => 'SYSTEM',
					'action' => 'reset_auth_key',
					'title' => 'Authentication key for user ' . $user['User']['id'] . ' (' . $user['User']['email'] . ')',
					'change' => 'authkey(' . $user['User']['authkey'] . ') => (' . $newkey . ')'
				));
				echo $newkey . PHP_EOL;
			} else {
				echo 'Could not update account for User.id = ', $user['User']['id'], PHP_EOL;
				echo json_encode($this->User->validationErrors) . PHP_EOL;
				$this->out(print_r($this->User->invalidFields(), true));
			}
		}
		exit;
	}
}
