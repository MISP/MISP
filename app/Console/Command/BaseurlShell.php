<?php
/**
 * Reset a password
 *
 * arg0 = baseurl
 * @deprecated
 */
class BaseurlShell extends AppShell {

    public $uses = array('Server');

    public function main()
    {
        $this->deprecated('cake admin setSetting MISP.baseurl [baseurl]');

        $baseurl = $this->args[0];
        $result = $this->Server->testBaseURL($baseurl);
        if (true !== $result) {
            echo $result . PHP_EOL;
        } else {
            $this->Server->serverSettingsSaveValue('MISP.baseurl', $baseurl);
            echo 'Baseurl updated. Have a very safe and productive day.', PHP_EOL;
        }
    }
}
