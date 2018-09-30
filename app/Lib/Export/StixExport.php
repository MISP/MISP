<?php

class StixExport
{
    private $__scripts_dir = APP . 'files/scripts/';
    private $__tmp_dir = null;
    private $__end_of_cmd = ' 2>' . APP . 'tmp/logs/exec-errors.log';
    private $__randomFileName = null;
    private $__baseurl = null;
    private $__org = null;
    private $__framing = null;
    private $__stix_file = null;
    private $__tmp_file = null;
    private $__n_events = 0;
    public $non_restrictive_export = true;

    public function handler($data, $options = array())
    {
        if ($this->__n_events != 0) {
            $this->__tmp_file->append(',');
        }
        App::uses('JSONConverterTool', 'Tools');
        $converter = new JSONConverterTool();
        $event = $converter->convert($data);
        $this->__tmp_file->append($event);
        unset($event);
        $this->__n_events += 1;
        if ($this->__n_events == 10) {
            $this->__append_parsed_stix();
        }
        return '';
    }

    public function header($options = array())
    {
        $this->__randomFileName = $this->generateRandomFileName();
        $this->__tmp_dir = $this->__scripts_dir . 'tmp/';
        $this->__baseurl = escapeshellarg(Configure::read('MISP.baseurl'));
        $this->__org = escapeshellarg(Configure::read('MISP.org'));
        $framing_file = $this->__scripts_dir . 'misp_framing.py ';
        $framing_cmd = 'python3 ' . $framing_file . 'stix ' . $this->__baseurl . ' ' . $this->__org . ' xml' . $this->__end_of_cmd;
        $this->__framing = json_decode(shell_exec($framing_cmd), true);
        $this->__stix_file = new File($this->__tmp_dir . $this->__randomFileName . '.stix');
        $this->__stix_file->write($this->__framing['header']);
        $this->__initialize_misp_file();
        return '';
    }

    public function footer($options = array())
    {
        $this->__parse_misp_events();
        $this->__stix_file->append($this->__framing['footer']);
        $stix_event = $this->__stix_file->read();
        $this->__stix_file->close();
        $this->__stix_file->delete();
        return $stix_event;
    }

    public function separator($options = array())
    {
        $this->__stix_file->append($this->__framing['separator']);
        return '';
    }

    private function __initialize_misp_file()
    {
        $this->__tmp_file = new File($this->__tmp_dir . $this->__randomFileName, true, 0644);
        $this->__tmp_file->write('{"response": [');
    }

    private function __append_parsed_stix()
    {
        $this->__parse_misp_events();
        $this->__initialize_misp_file();
        $this->__n_events = 0;
    }

    private function __parse_misp_events()
    {
        $this->__tmp_file->append(']}');
        $scriptFile = $this->__scripts_dir . 'misp2stix.py';
        $result = shell_exec('python3 ' . $scriptFile . ' ' . $this->__randomFileName . ' xml ' . $this->__baseurl . ' ' . $this->__org . $this->__end_of_cmd);
        $decoded = json_decode($result, true);
        $this->__tmp_file->close();
        $this->__tmp_file->delete();
        if (!isset($decoded['success']) || !$decoded['success']) {
            return '';
        }
        $file = new File($this->__tmp_dir . $this->__randomFileName . '.out');
        $stix_event = $file->read();
        $file->close();
        $file->delete();
        $this->__stix_file->append($stix_event);
        unset($stix_event);
    }

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }
}
