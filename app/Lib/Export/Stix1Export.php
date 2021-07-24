<?php

App::uses('StixExport', 'Export');

class Stix1Export extends StixExport
{
    protected $__attributes_limit = 15000;
    private $__script_name = 'misp2stix.py ';
    private $__baseurl = null;
    private $__org = null;

    protected function __initiate_framing_params()
    {
        $this->__baseurl = escapeshellarg(Configure::read('MISP.baseurl'));
        $this->__org = escapeshellarg(Configure::read('MISP.org'));
        $my_server = ClassRegistry::init('Server');
        return $my_server->getPythonVersion() . ' ' . $this->__framing_script . ' stix1 -v ' . $this->__version . ' -n ' . $this->__baseurl . ' -o ' . $this->__org . ' -f ' . $this->__return_format . ' ' . $this->__end_of_cmd;
    }

    protected function __parse_misp_events($filename)
    {
        $scriptFile = $this->__scripts_dir . $this->__script_name;
        $my_server = ClassRegistry::init('Server');
        return shell_exec($my_server->getPythonVersion() . ' ' . $scriptFile . ' ' . $filename . ' ' . $this->__return_format . ' ' . $this->__baseurl . ' ' . $this->__org . $this->__end_of_cmd);
    }
}
