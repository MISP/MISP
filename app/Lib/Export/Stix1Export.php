<?php

App::uses('StixExport', 'Export');

class Stix1Export extends StixExport
{
    protected $__attributes_limit = 15000;
    protected $__default_version = '1.1.1';
    protected $__sane_versions = array('1.1.1', '1.2');
    private $__script_name = 'misp2stix.py ';
    private $__baseurl = null;
    private $__org = null;

    protected function __initiate_framing_params()
    {
        $this->__baseurl = escapeshellarg(Configure::read('MISP.baseurl'));
        $this->__org = escapeshellarg(Configure::read('MISP.org'));
        $my_server = ClassRegistry::init('Server');
        return $my_server->getPythonVersion() . ' ' . $this->__framing_script . ' stix1 -s ' . $this->__scope . ' -v ' . $this->__version . ' -n ' . $this->__baseurl . ' -o ' . $this->__org . ' -f ' . $this->__return_format . ' ' . $this->__end_of_cmd;
    }

    protected function __parse_misp_data($filenames)
    {
        $scriptFile = $this->__scripts_dir . $this->__script_name;
        $my_server = ClassRegistry::init('Server');
        $result = shell_exec($my_server->getPythonVersion() . ' ' . $scriptFile . '-v ' . $this->__version . ' -f ' . $this->__return_format . ' -o ' . $this->__org . ' -i ' . $this->__tmp_dir . $filenames . ' -s ' . $this->__scope . $this->__end_of_cmd);
        $decoded = json_decode($result, true);
        if (!isset($decoded['success']) || !$decoded['success']) {
            $this->__delete_temporary_files();
            $error = !empty($decoded['error']) ? $decoded['error'] : $result;
            return 'Error while processing your query: ' . $error;
        }
        if (!empty($decoded['filenames'])) {
            foreach ($this->__filenames as $f => $filename) {
                @unlink($this->__tmp_dir . $filename);
            }
            foreach ($decoded['filenames'] as $filename) {
                $this->__write_stix_content($filename);
            }
        } else {
            foreach ($this->__filenames as $f => $filename) {
                $content_filename = $this->__tmp_dir . $filename;
                $this->__write_stix_content($content_filename . '.out');
                @unlink($content_filename);
            }
        }
    }
}
