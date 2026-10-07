<?php

/**
 * MsgdPlug Plugin
 *
 * @author     TETRAPI SA, Lino Pacheco
 * @license    AGPL-3.0
 */

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 4) . '/Lib/Enum/MsgdPluginConfigEnum.php';
require_once dirname(__DIR__, 4) . '/Lib/Utility/MsgdLoggerUtility.php';

App::uses('CakeLog', 'Log');
App::uses('Configure', 'Core');

/**
 * Tests for the logger utility.
 *
 * @package    MsgdPlug
 * @subpackage MsgdPlug.Test.Case.Lib.Utility
 */
class MsgdLoggerUtilityTest extends TestCase
{
    private string $logDirectory;

    /**
     * Configures the temporary log stream.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->logDirectory = sys_get_temp_dir()
            . DIRECTORY_SEPARATOR
            . 'msgd-logger-' . uniqid('', true);

        mkdir($this->logDirectory, 0777, true);

        CakeLog::config('msgd_logger_test', [
            'engine' => 'FileLog',
            'path' => $this->logDirectory . DIRECTORY_SEPARATOR,
            'file' => 'msgd_test',
        ]);

        Configure::write(
            MsgdPluginConfigEnum::debug->value,
            false
        );
    }

    /**
     * Removes the temporary log stream and files.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        CakeLog::drop('msgd_logger_test');

        foreach (
            glob(
                $this->logDirectory
                . DIRECTORY_SEPARATOR
                . '*.log'
            ) ?: [] as $file
        ) {
            unlink($file);
        }

        rmdir($this->logDirectory);

        parent::tearDown();
    }

    /**
     * Verifies that a normal message is sanitized and written.
     *
     * @return void
     */
    public function testLogWritesSanitizedMessage(): void
    {
        MsgdLoggerUtility::log(
            'warning',
            "  First\r\nSecond\tThird  "
        );

        $log = $this->readLog();

        $this->assertStringContainsString(
            'MsgdPlug: First Second Third',
            $log
        );
    }

    /**
     * Verifies that debug messages are ignored when debug logging is disabled.
     *
     * @return void
     */
    public function testDebugMessageIsIgnoredWhenDisabled(): void
    {
        MsgdLoggerUtility::log('debug', 'Debug message');

        $this->assertSame('', $this->readLog());
    }

    /**
     * Verifies that debug messages are written when debug logging is enabled.
     *
     * @return void
     */
    public function testDebugMessageIsWrittenWhenEnabled(): void
    {
        Configure::write(
            MsgdPluginConfigEnum::debug->value,
            true
        );

        MsgdLoggerUtility::log('debug', 'Debug message');

        $this->assertStringContainsString(
            'MsgdPlug: Debug message',
            $this->readLog()
        );
    }

    /**
     * Verifies that empty messages are ignored.
     *
     * @return void
     */
    public function testEmptyMessageIsIgnored(): void
    {
        MsgdLoggerUtility::log('error', '');

        $this->assertSame('', $this->readLog());
    }

    /**
     * Verifies that messages containing only control characters are ignored.
     *
     * @return void
     */
    public function testControlOnlyMessageIsIgnored(): void
    {
        MsgdLoggerUtility::log('error', "\r\n\t");

        $this->assertSame('', $this->readLog());
    }

    /**
     * Verifies that oversized messages are truncated.
     *
     * @return void
     */
    public function testLongMessageIsTruncated(): void
    {
        $message = str_repeat(
            'A',
            MsgdLoggerUtility::MAX_LOG_LENGTH + 100
        );

        MsgdLoggerUtility::log('error', $message);

        $log = $this->readLog();

        $this->assertStringContainsString(
            str_repeat('A', MsgdLoggerUtility::MAX_LOG_LENGTH),
            $log
        );

        $this->assertStringContainsString(
            '... [TRUNCATED]',
            $log
        );

        $this->assertStringNotContainsString(
            str_repeat('A', MsgdLoggerUtility::MAX_LOG_LENGTH + 1),
            $log
        );
    }

    /**
     * Verifies that exception details and context are written.
     *
     * @return void
     */
    public function testLogExceptionWritesExceptionDetails(): void
    {
        $exception = new RuntimeException('Test exception');

        MsgdLoggerUtility::logException(
            $exception,
            " Test\r\ncontext\tmessage "
        );

        $log = $this->readLog();

        $this->assertStringContainsString(
            '[Context: Test context message]',
            $log
        );

        $this->assertStringContainsString(
            'Error: Test exception',
            $log
        );

        $this->assertStringContainsString(
            'Stack Trace:',
            $log
        );
    }

    /**
     * Reads all generated log files.
     *
     * @return string
     */
    private function readLog(): string
    {
        $content = '';

        foreach (
            glob(
                $this->logDirectory
                . DIRECTORY_SEPARATOR
                . '*.log'
            ) ?: [] as $file
        ) {
            $content .= file_get_contents($file);
        }

        return $content;
    }
}
