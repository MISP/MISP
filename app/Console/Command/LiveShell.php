<?php
/*
 * Reset a password
 *
 * arg0 = baseurl
 */
class LiveShell extends AppShell {

	public $uses = array('Server');

	public function main() {
		$live = $this->args[0];
		if ($live != 0 && $live != 1) {
			echo 'Invalid parameters. Usage: /var/www/MISP/app/Console/cake Live [0|1]';
		} else {
			$this->Server->serverSettingsSaveValue('MISP.live', $live);
		}
		$status = $live ? 'MISP is now live. Users can now log in.' : 'MISP is now disabled. Only site admins can log in.';
		echo $status;
	}
}
