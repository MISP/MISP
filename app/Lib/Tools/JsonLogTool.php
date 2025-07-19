<?php
App::uses('JsonTool', 'Tools');

class JsonLogTool
{
    public $logFilePath = APP . 'tmp/logs/error.log.ndjson';

    public function __construct()
    {
        $this->logFilePath = Configure::read('MISP.log_errors_ndjson_path') ? Configure::read('MISP.log_errors_ndjson_path') : $this->logFilePath;
        if (file_exists($this->logFilePath) && filesize($this->logFilePath) > (1024 * 1024 * 10)) {
            rename($this->logFilePath, $this->logFilePath . '.' . time());
        }

    }

    public function createLogEntry($data)
    {
        $data['date'] = date('Y-m-d H:i:s');
        $data['timestamp'] = time();
        ksort($data);
        file_put_contents($this->logFilePath, JsonTool::encode($data) . "\n", FILE_APPEND | LOCK_EX);
    }
}