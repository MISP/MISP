<?php
App::uses('StixExport', 'Export');

class Stix1Export extends StixExport
{
    protected $__attributes_limit = 15000;
    protected $__default_version = '1.1.1';
    protected $__sane_versions = array('1.1.1', '1.2');

    protected function __initiate_framing_params()
    {
        return [
            ProcessTool::pythonBin(),
            $this->__framing_script,
            'stix1',
            '-s', $this->__scope,
            '-v', $this->__version,
            '-n', Configure::read('MISP.baseurl'),
            '-o', Configure::read('MISP.org'),
            '-f', $this->__return_format,
        ];
    }

    protected function __parse_misp_data()
    {
        $command = [
            ProcessTool::pythonBin(),
            $this->__scripts_dir . 'misp2stix.py',
            '-s', $this->__scope,
            '-v', $this->__version,
            '-f', $this->__return_format,
            '-o', Configure::read('MISP.org'),
            '-i',
        ];
        $command = array_merge($command, $this->__filenames);
        return ProcessTool::execute($command, null, true);
    }
}
