<?php

class StixExport
{
    private $__tmpDir = APP . 'files/scripts/';
    private $end_of_cmd = ' 2>' . APP . 'tmp/logs/exec-errors.log';
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
        $scriptFile = $this->__tmpDir . 'misp2stix.py';
        $result = shell_exec('python3 ' . $scriptFile . ' ' . $randomFileName . ' xml ' . $this->baseurl . ' ' . $this->org . $this->end_of_cmd);
        $decoded = json_decode($result, true);
        $tempFile->close();
        $tempFile->delete();
        if (!isset($decoded['success']) || !$decoded['success']) {
            return '';
        }
        $file = new File($tmpDir . $randomFileName . '.out');
        $stix_event = $file->read();
        $stix_event = '            ' . substr($file->read(), 0, -1);
        $stix_event = explode("\n", $stix_event);
        $stix_event[0] = str_replace("STIX_Package", "Package", $stix_event[0]);
        $stix_event[count($stix_event)-1] = str_replace("STIX_Package", "Package", $stix_event[count($stix_event)-1]);
        $stix_event = implode("\n", $stix_event);
        $stix_event = str_replace("\n", "\n            ", $stix_event) . "\n";
        $file->close();
        $file->delete();
        return $stix_event;
    }

    public function header($options = array())
    {
        $this->baseurl = escapeshellarg(Configure::read('MISP.baseurl'));
        $this->org = escapeshellarg(Configure::read('MISP.org'));
        $framing_file = $this->__tmpDir . 'misp_framing.py ';
        $framing_cmd = 'python3 ' . $framing_file . 'stix ' . $this->baseurl . ' ' . $this->org . ' xml' . $this->end_of_cmd;
        $this->framing = json_decode(shell_exec($framing_cmd), true);
        return $this->framing['header'];
    }

    public function footer($options = array())
    {
        return $this->framing['footer'];
    }

    public function separator($options = array())
    {
        return $this->framing['separator'];
    }

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }
}
