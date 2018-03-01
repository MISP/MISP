<?php
/*
 * Reset a password
 *
 * arg0 = baseurl
 */
class BaseurlShell extends AppShell {

	public $uses = array('Server');

	public function main() {
		$baseurl = $this->args[0];
		$this->Server->serverSettingsSaveValue('MISP.baseurl', $baseurl);
		echo 'Baseurl updated. Have a very safe and productive day.', PHP_EOL;
	}
}
