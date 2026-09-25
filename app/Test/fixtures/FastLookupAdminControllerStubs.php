<?php
require_once __DIR__ . '/FastLookupControllerStubs.php';
class FastLookupIndexManager
{
    public static $metrics = [];
    public function status($metrics = false) { self::$metrics[] = $metrics; return ['status' => 'warming', 'scope' => FastLookupConfig::scope(), 'progress' => ['processed_events' => 0, 'total_events' => 10]]; }
}
class Job
{
    const WORKER_DEFAULT = 'default';
    public $created = [];
    public $statuses = [];
    public function createJob(...$args) { $this->created[] = $args; return 47; }
    public function saveStatus(...$args) { $this->statuses[] = $args; }
}
class BackgroundJobsTool
{
    const DEFAULT_QUEUE = 'default';
    const CMD_ADMIN = 'admin';
}
class FastLookupAdminQueue
{
    public $calls = [];
    public $exception;
    public function enqueue(...$args)
    {
        $this->calls[] = $args;
        if ($this->exception) { throw $this->exception; }
        return 'queued-job';
    }
}
class FastLookupAdminServer
{
    public $queue;
    public function __construct() { $this->queue = new FastLookupAdminQueue(); }
    public function getBackgroundJobsTool() { return $this->queue; }
}
require_once __DIR__ . '/../../Controller/ServersController.php';
