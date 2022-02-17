<?php
App::uses('StixExport', 'Export');

class Stix2Export extends StixExport
{
    protected $__attributes_limit = 15000;
    protected $__default_version = '2.0';
    protected $__sane_versions = array('2.0', '2.1');

    protected function __initiate_framing_params()
    {
        return [
            ProcessTool::pythonBin(),
            $this->__framing_script,
            'stix2',
            '-v', $this->__version,
            '--uuid', CakeText::uuid(),
        ];
    }

    protected function __parse_misp_data()
    {
        $scriptFile = $this->__scripts_dir . 'stix2/misp2stix2.py';
        $command = [
            ProcessTool::pythonBin(),
            $scriptFile,
            '-v', $this->__version,
            '-i',
        ];
        $command = array_merge($command, $this->__filenames);
        $result = ProcessTool::execute($command, null, true);
        $result = preg_split("/\r\n|\n|\r/", trim($result));
        return end($result);
    }
}
