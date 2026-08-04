<?php
App::uses('StixExport', 'Export');

class Stix2Export extends StixExport
{
    protected $__attributes_limit = 15000;
    protected $__default_version = '2.1';
    protected $__sane_versions = array('2.0', '2.1');

    protected function __initiate_framing_params()
    {
        return [
            ProcessTool::pythonBin(),
            self::FRAMING_SCRIPT,
            'stix2',
            '-v', $this->__version,
            '--uuid', CakeText::uuid(),
        ];
    }

    /**
     * @return string
     * @throws Exception
     */
    protected function __parse_misp_data()
    {
        $scriptFile = self::SCRIPTS_DIR . 'stix2/misp2stix2.py';
        $command = [
            ProcessTool::pythonBin(),
            $scriptFile,
            '-v', $this->__version,
            '-i',
        ];
        $command = array_merge($command, $this->__filenames);
        try {
            $result = ProcessTool::execute($command, null, true);
        } catch (ProcessException $e) {
            $result = $e->stdout();
        }
        $result = preg_split("/\r\n|\n|\r/", trim($result));
        return end($result);
    }
}
