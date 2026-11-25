<?php
class AppModel
{
    public $db;
    public $id;
    public $data;
    public $alias = 'Event';
    public $Attribute;
    public function getDataSource() { return $this->db; }
    protected function isTriggerCallable($id): bool { return false; }
    protected function pubToZmq($name) { return false; }
    public function log($message, $level) {}
}
$previousErrorReporting = error_reporting();
error_reporting($previousErrorReporting & ~E_DEPRECATED);
try {
    require_once __DIR__ . '/../../Model/Event.php';
    require_once __DIR__ . '/../../Model/MispAttribute.php';
} finally {
    error_reporting($previousErrorReporting);
}
