<?php

class Stix2Export
{
    private $end_of_cmd = ' 2>' . APP . 'tmp/logs/exec-errors.log';
    private $__tmpDir = APP . 'files/scripts/';
    public $non_restrictive_export = true;
    public function handler($data, $options = array())
    {
        $randomFileName = $this->generateRandomFileName();
        $tmpDir = $this->__tmpDir . 'tmp/';
        App::uses('JSONConverterTool', 'Tools');
        $converter = new JSONConverterTool();
        $event = $converter->convert($data);
        $tempFile = new File($tmpDir . $randomFileName, true, 0644);
        $tempFile->write($event);
        unset($event);
        $scriptFile = $this->__tmpDir . 'stix2/misp2stix2.py';
        $stix_cmd = 'python3 ' . $scriptFile . ' ' . $tempFile->path . ' org' . $this->end_of_cmd;
        $result = shell_exec($stix_cmd);
        $decoded = json_decode($result, true);
        $tempFile->close();
        $tempFile->delete();
        if (!isset($decoded['success']) || !$decoded['success']) {
            return '';
        }
        $file = new File($tmpDir . $randomFileName . '.out');
        $stix_event = $file->read();
        $file->close();
        $file->delete();
        return $stix_event;
    }

    public function header()
    {
        $framing_file = $this->__tmpDir . 'misp_framing.py ';
        $framing_cmd = 'python3 ' . $framing_file . 'stix2 ' . escapeshellarg(CakeText::uuid()) . $this->end_of_cmd;
        $this->framing = json_decode(shell_exec($framing_cmd), true);
        return $this->framing['header'];
    }

    public function footer()
    {
        return $this->framing['footer'];
    }

    public function separator()
    {
        return $this->framing['separator'];
    }

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }
}
