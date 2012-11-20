<?php
/*
 * Reset a password
 *
 * arg0 = email
 * arg1 = new password
 */
class PasswordShell extends AppShell {

	public $uses = array('User');

	public function main() {
		// get the users that need their password hashed
		$results = $this->User->findByEmail($this->args[0]);
		//$this->out(print_r($results, true));
		App::import('Component','Auth');
		$this->Auth = new AuthComponent(new ComponentCollection());

		$count = count($results);

		$results['User']['password'] = $this->args[1];
		$results['User']['confirm_password'] = $this->args[1];

		if (!$this->User->save($results)) {
			echo 'Could not update account for User.id = ', $results['User']['id'], PHP_EOL;
			debug($this->User->validationErrors);
			$this->out(print_r($this->User->invalidFields(), true));
		}

		echo 'Updated ',  PHP_EOL;
		exit;
	}
}