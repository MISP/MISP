<?php
class ClassRegistry
{
    public static $attribute;
    public static function init($name) { return $name === 'Job' ? new Job() : self::$attribute; }
}
class AppShell
{
    public $Job;
    public $MispAttribute;
    public $args = [];
    public $output = [];
    public function out($message) { $this->output[] = $message; }
    public function error($message) { throw new RuntimeException($message); }
}
class Job
{
    const WORKER_DEFAULT = 'default';
    public $tool;
    public $success;
    public function __construct() { $this->tool = new BackgroundJobsTool(); }
    public function createJob(...$args) { return 5; }
    public function saveProgress(...$args) {}
    public function saveStatus($jobId, $success, $message = null) { $this->success = $success; }
    public function getBackgroundJobsTool() { return $this->tool; }
}
class BackgroundJobsTool
{
    const DEFAULT_QUEUE = 'default';
    const CMD_ADMIN = 'admin';
    public $queued = [];
    public function enqueue(...$args) { $this->queued[] = $args; }
}
class FastLookupIndex extends FastLookupLifecycleIndex
{
    private static $shared;
    public function __construct(...$args)
    {
        if (self::$shared === null) { self::$shared = ['meta' => [], 'events' => []]; }
        $this->meta =& self::$shared['meta'];
        $this->events =& self::$shared['events'];
    }
}
