<?php
/**
 * A MISP older than 3.0 stores text in utf8mb3 columns, so 4-byte characters
 * are sent to it, and served to it, as `?`: SyncTool::withoutFourByteChars()
 * and its streaming variant, the requester gate, and the push-side version
 * check in ServerSyncTool.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Lib/Tools/SyncTool.php';
require_once __DIR__ . '/../Lib/Tools/ServerSyncTool.php';

class FourByteRemoteSync extends ServerSyncTool
{
    private $injectedInfo;

    public function __construct($info)
    {
        $this->injectedInfo = $info;
    }

    public function info()
    {
        if ($this->injectedInfo instanceof Exception) {
            throw $this->injectedInfo;
        }
        return $this->injectedInfo;
    }
}

class SyncFourByteShapingTest extends TestCase
{
    const EMOJI = "\u{1F600}";

    protected function tearDown(): void
    {
        Configure::write('CurrentRequesterMispVersion', null);
    }

    public function testEveryFourByteCharacterBecomesOneQuestionMark()
    {
        $text = '{"info":"a' . self::EMOJI . 'b' . "\u{10FFFF}" . self::EMOJI . '"}';
        $this->assertSame('{"info":"a?b??"}', SyncTool::withoutFourByteChars($text));
    }

    public function testOneTwoAndThreeByteCharactersAreKept()
    {
        $text = "caf\u{E9} \u{20AC} \u{4E2D}\u{6587} \u{FFFF} plain";
        $this->assertSame($text, SyncTool::withoutFourByteChars($text));
    }

    public function testInvalidUtf8DoesNotLoseTheText()
    {
        $text = "a\xFF" . self::EMOJI . "\xC3";
        $this->assertSame("a\xFF?\xC3", SyncTool::withoutFourByteChars($text));
    }

    private function through($body)
    {
        $file = new TmpFileTool();
        $file->write($body);
        $out = SyncTool::withoutFourByteCharsInFile($file);
        return $out->intoString();
    }

    public function testAFileIsShapedLikeAString()
    {
        $body = str_repeat('x' . self::EMOJI . "\u{E9}", 40000);
        $this->assertSame(SyncTool::withoutFourByteChars($body), $this->through($body));
    }

    public function testACharacterSplitBetweenTwoChunksIsStillShaped()
    {
        // The reader hands out 65,536-byte chunks: put an emoji across every
        // offset of the first boundary.
        foreach ([0, 1, 2, 3] as $into) {
            $body = str_repeat('a', 65536 - $into) . self::EMOJI . 'tail';
            $this->assertSame(str_repeat('a', 65536 - $into) . '?tail', $this->through($body), "split after $into bytes");
        }
        $body = str_repeat('a', 65535) . self::EMOJI . self::EMOJI . 'z';
        $this->assertSame(str_repeat('a', 65535) . '??z', $this->through($body));
    }

    public function testATruncatedCharacterAtTheEndOfAFileSurvives()
    {
        $body = 'abc' . substr(self::EMOJI, 0, 3);
        $this->assertSame($body, $this->through($body));
    }

    public function testOnlyAMispOlderThan30IsTheRequesterToShapeFor()
    {
        foreach (['2.4.155' => true, '2.5.50' => true, '3.0.0' => false, '3.1.0' => false] as $version => $below) {
            Configure::write('CurrentRequesterMispVersion', $version);
            $this->assertSame($below, SyncTool::requesterBelow30(), $version);
        }
        Configure::write('CurrentRequesterMispVersion', null);
        $this->assertFalse(SyncTool::requesterBelow30(), 'an API client or the CLI');
    }

    public function testThePushShapesForARemoteBelow30Only()
    {
        $below = new ReflectionMethod('ServerSyncTool', 'remoteBelow30');
        $below->setAccessible(true);
        foreach (['2.4.150' => true, '2.5.42' => true, '3.0.0' => false, '3.2.1' => false] as $version => $expected) {
            $this->assertSame($expected, $below->invoke(new FourByteRemoteSync(['version' => $version])), $version);
        }
        $this->assertFalse($below->invoke(new FourByteRemoteSync(new Exception('unreachable'))), 'a remote whose version cannot be read');
    }
}
