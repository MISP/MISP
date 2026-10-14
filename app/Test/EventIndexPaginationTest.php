<?php
use PHPUnit\Framework\TestCase;

class EventIndexPaginationTest extends TestCase
{
    /** @dataProvider scenarios */
    public function testEventIndexPagination($scenario)
    {
        $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(
            __DIR__ . '/fixtures/event_index_sync.php'
        ) . ' ' . escapeshellarg($scenario) . ' 2>&1';
        exec($command, $output, $status);
        $this->assertSame(0, $status, implode("\n", $output));
        $this->assertContains('PASS ' . $scenario, $output);
    }

    public function scenarios()
    {
        $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(
            __DIR__ . '/fixtures/event_index_sync.php'
        ) . ' --list';
        $scenarios = json_decode(shell_exec($command), true, 512,
            JSON_THROW_ON_ERROR);
        return array_map(function ($scenario) { return [$scenario]; }, $scenarios);
    }
}
