<?php
/**
 * Image dimension guard unit tests (AttachmentTool, EventGraph).
 *
 * The decode step is replaced by test doubles: real GD never decodes the
 * oversized header image in any run.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!defined('APP')) {
    define('APP', dirname(__DIR__) . '/');
}

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/AttachmentTool.php';

class AttachmentToolImageSizeModelStub
{
}

class RecordingAttachmentTool extends AttachmentTool
{
    public static $decodeCalls = 0;

    protected static function decodeImage($data)
    {
        self::$decodeCalls++;
        return imagecreatetruecolor(1, 1);
    }
}

class AttachmentToolImageSizeTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('gd')) {
            $this->markTestSkipped('gd extension is not loaded');
        }
        RecordingAttachmentTool::$decodeCalls = 0;
    }

    private static function chunk($type, $data)
    {
        return pack('N', strlen($data)) . $type . $data
            . pack('N', crc32($type . $data));
    }

    private static function pngHeader($width, $height)
    {
        return "\x89PNG\r\n\x1a\n"
            . self::chunk('IHDR', pack('NNCCCCC', $width, $height, 8, 6, 0, 0, 0))
            . self::chunk('IEND', '');
    }

    private static function eventGraph()
    {
        // Loaded at run time: an AppModel stub declared while the suite loads
        // its files would shadow the fuller ones other test files need.
        if (!class_exists('AppModel', false)) {
            class_alias('AttachmentToolImageSizeModelStub', 'AppModel');
        }
        require_once __DIR__ . '/../Model/EventGraph.php';
        return new class extends EventGraph {
            public function __construct()
            {
            }

            protected function createImage($data)
            {
                return RecordingAttachmentTool::createImageFromString($data);
            }
        };
    }

    private static function smallPng()
    {
        $img = imagecreatetruecolor(4, 4);
        ob_start();
        imagepng($img);
        return ob_get_clean();
    }

    public function testHugeHeaderIsNotDecodedByResizeImage()
    {
        $tool = new RecordingAttachmentTool();
        try {
            $tool->resizeImage(self::pngHeader(20000, 20000), 200, 200);
            $this->fail('Oversized image was accepted');
        } catch (Exception $e) {
            $this->assertSame('Image is not valid.', $e->getMessage());
        }
        $this->assertSame(0, RecordingAttachmentTool::$decodeCalls);
    }

    public function testZeroDimensionIsNotDecoded()
    {
        $this->assertFalse(RecordingAttachmentTool::createImageFromString(self::pngHeader(0, 10)));
        $this->assertFalse(RecordingAttachmentTool::createImageFromString('not an image'));
        $this->assertSame(0, RecordingAttachmentTool::$decodeCalls);
    }

    public function testSmallImageIsDecodedAndResized()
    {
        $this->assertNotFalse(RecordingAttachmentTool::createImageFromString(self::smallPng()));
        $this->assertSame(1, RecordingAttachmentTool::$decodeCalls);

        $out = (new AttachmentTool())->resizeImage(self::smallPng(), 2, 2);
        $this->assertSame([2, 2], array_slice(getimagesizefromstring($out), 0, 2));
    }

    public function testHugeHeaderIsNotDecodedByEventGraph()
    {
        $graph = self::eventGraph();
        $row = ['EventGraph' => ['preview_img' => 'data:image/png;base64,' . base64_encode(self::pngHeader(20000, 20000))]];
        try {
            $graph->getPictureData($row);
            $this->fail('Oversized image was accepted');
        } catch (Exception $e) {
            $this->assertSame('Image is not valid.', $e->getMessage());
        }
        $this->assertSame(0, RecordingAttachmentTool::$decodeCalls);
    }

    public function testSmallImageIsDecodedByEventGraph()
    {
        $graph = self::eventGraph();
        $row = ['EventGraph' => ['preview_img' => 'data:image/png;base64,' . base64_encode(self::smallPng())]];
        $this->assertNotSame('', $graph->getPictureData($row));
        $this->assertSame(1, RecordingAttachmentTool::$decodeCalls);
    }
}
