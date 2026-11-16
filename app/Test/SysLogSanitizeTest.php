<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';
if (!defined('LOGS')) {
    define('LOGS', sys_get_temp_dir() . '/');
}

require_once __DIR__ . '/../Plugin/SysLog/Lib/SysLog.php';

class SysLogCaptureStub extends SysLog
{
    public $lines = array();

    protected function emit($type, $message)
    {
        $this->lines[] = array($type, $message);
        return true;
    }
}

class SysLogSanitizeTest extends TestCase
{
    public function testWhitespaceControlsBecomeSpace()
    {
        $this->assertSame('a b c d e f', SysLog::sanitize("a\nb\rc\td\x0Be\x0Cf"));
        $this->assertSame('a b', SysLog::sanitize("a\r\n\tb"));
        $this->assertSame('a b', SysLog::sanitize("a\nb"));
    }

    public function testOtherControlsAreRemoved()
    {
        $this->assertSame('a[31mb', SysLog::sanitize("a\x1b[31m\x00b\x7f"));
        $this->assertSame('ab', SysLog::sanitize("a\x00\x07\x1f\x7fb"));
    }

    public function testUtf8Survives()
    {
        $text = "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80 \xE6\x97\xA5\xE6\x9C\xAC";
        $this->assertSame($text, SysLog::sanitize($text));
        $this->assertSame("\xC3\xA9 \xC3\xA9", SysLog::sanitize("\xC3\xA9\n\xC3\xA9"));
    }

    public function testInvalidUtf8IsNotNull()
    {
        $this->assertSame("a\xFF\xFEb", SysLog::sanitize("a\xFF\x01\xFEb"));
        $this->assertSame("\xC3", SysLog::sanitize("\xC3\x00"));
        $this->assertSame('', SysLog::sanitize(null));
    }

    public function testWriteSanitisesEveryEntry()
    {
        $log = new SysLogCaptureStub(array('ident' => 'misp-test', 'to_stderr' => false));
        $log->write(LOG_INFO, "edit -- title\nFORGED\x1b[2J -- desc");
        $log->write(LOG_NOTICE, "login\r\n-- x\x00");
        $this->assertSame(array(
            array(LOG_INFO, 'edit -- title FORGED[2J -- desc'),
            array(LOG_NOTICE, 'login -- x'),
        ), $log->lines);
    }

    public function testJsonEntryIsUnchanged()
    {
        $json = json_encode(array('title' => "a\nb\x1b", 'u' => "\xC3\xA9"));
        $log = new SysLogCaptureStub(array('ident' => 'misp-test', 'to_stderr' => false));
        $log->write(LOG_INFO, $json);
        $this->assertSame($json, $log->lines[0][1]);
    }
}
