<?php
App::uses('StixExport', 'Export');

class Stix1Export extends StixExport
{
    protected $__attributes_limit = 15000;
    protected $__default_version = '1.1.1';
    protected $__sane_versions = array('1.1.1', '1.2');

    protected function __initiate_framing_params()
    {
        $baseurl = escapeshellarg(Configure::read('MISP.baseurl'));
        $org = escapeshellarg(Configure::read('MISP.org'));
        return $this->pythonBin() . ' ' . $this->__framing_script . ' stix1 -v ' . $this->__version . ' -n ' . $baseurl . ' -o ' . $org . ' -f ' . $this->__return_format . ' ' . $this->__end_of_cmd;
    }

    protected function __parse_misp_events(array $filenames)
    {
        $org = escapeshellarg(Configure::read('MISP.org'));
        $filenames = implode(' ', $filenames);
        $scriptFile = $this->__scripts_dir . 'misp2stix.py';
        $command = $this->pythonBin() . ' ' . $scriptFile . ' -v ' . $this->__version . ' -f ' . $this->__return_format . ' -o ' . $org . ' -i ' . $filenames . $this->__end_of_cmd;
        return shell_exec($command);
    }
}
