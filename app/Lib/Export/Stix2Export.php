<?php

App::uses('StixExport', 'Export');

class Stix2Export extends StixExport
{
    protected $__attributes_limit = 15000;
    private $__script_name = 'stix2/misp2stix2.py ';

    protected function initiate_framing_params()
    {
        $framing_file = $this->__scripts_dir . 'misp_framing.py ';
        $my_server = ClassRegistry::init('Server');
        return $my_server->getPythonVersion() . ' ' . $framing_file . $this->__return_type . ' ' . escapeshellarg(CakeText::uuid()) . $this->__end_of_cmd;
    }

    protected function __parse_misp_events($filename)
    {
        $scriptFile = $this->__scripts_dir . $this->__script_name;
        $filename = $this->__scripts_dir . 'tmp/' . $filename;
        $my_server = ClassRegistry::init('Server');
        $result = shell_exec($my_server->getPythonVersion() . ' ' . $scriptFile . ' ' . $filename . $this->__end_of_cmd);
        $result = preg_split("/\r\n|\n|\r/", trim($result));
        return end($result);
    }
}
