<?php
/** Records the waits for a busy worker lease instead of sleeping. Load after FastLookupIndexManager.php. */
class FastLookupPausingManager extends FastLookupIndexManager
{
    public $pauses = [];
    protected function pause(int $milliseconds): void { $this->pauses[] = $milliseconds; }
}
