<?php

App::uses('StixExport', 'Export');

class Stix2Export extends StixExport
{
    protected $__attributes_limit = 15000;
    private $__script_name = 'stix2/misp2stix2.py ';

    protected function __initiate_framing_params()
    {
        $my_server = ClassRegistry::init('Server');
        return $my_server->getPythonVersion() . ' ' . $this->__framing_script . ' stix2 -v ' . $this->__version . ' --uuid ' . escapeshellarg(CakeText::uuid()) . $this->__end_of_cmd;
    }

    protected function __parse_misp_events()
    {
        $scriptFile = $this->__scripts_dir . $this->__script_name;
        $filenames = implode(' ' . $this->__tmp_dir, $this->__filenames);
        $my_server = ClassRegistry::init('Server');
        $result = shell_exec($my_server->getPythonVersion() . ' ' . $scriptFile . ' ' . $this->__tmp_dir . $filenames . $this->__end_of_cmd);
        $result = preg_split("/\r\n|\n|\r/", trim($result));
        return end($result);
    }
}
