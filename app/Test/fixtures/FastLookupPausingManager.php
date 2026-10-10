<?php
/**
 * Runs on the fake filter's clock: waits for a busy worker lease advance it
 * instead of sleeping, and lease deadlines are measured on it.
 * Load after FastLookupIndexManager.php.
 */
class FastLookupPausingManager extends FastLookupIndexManager
{
    public $pauses = [];
    protected function pause(int $milliseconds): void { $this->pauses[] = $milliseconds; $this->filter()->clock += $milliseconds; }
    protected function now(): float { return (float)$this->filter()->clock; }
}
