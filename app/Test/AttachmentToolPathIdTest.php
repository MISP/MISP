<?php
/**
 * Attachment paths are built from event and attribute ids: anything but a
 * plain integer is refused before a path is formed.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!defined('APP')) {
    define('APP', dirname(__DIR__) . '/');
}
if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
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

class AttachmentToolPathIdTest extends TestCase
{
    private function assertId($id)
    {
        $method = new ReflectionMethod(AttachmentTool::class, 'assertId');
        $method->setAccessible(true);
        $method->invoke(new AttachmentTool(), $id);
    }

    public function validIds()
    {
        return [[0], [838], ['838'], ['12345678901234567890']];
    }

    /**
     * @dataProvider validIds
     */
    public function testPlainIntegerIdsAccepted($id)
    {
        $this->assertId($id);
        $this->addToAssertionCount(1);
    }

    public function invalidIds()
    {
        return [
            ['838.php'], ['../838'], ['838/../../webroot'], ['-1'], [' 838'],
            ['838 '], [''], [null], [false], [true], [8.38], [[838]],
        ];
    }

    /**
     * @dataProvider invalidIds
     */
    public function testOtherIdsRefused($id)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->assertId($id);
    }

    public function testSaveRefusesAttributeIdBeforeWriting()
    {
        $this->expectException(InvalidArgumentException::class);
        (new AttachmentTool())->save('1', '838.php', 'x');
    }

    public function testSaveRefusesEventPath()
    {
        $this->expectException(InvalidArgumentException::class);
        (new AttachmentTool())->save('1/..', '838', 'x');
    }

    public function testShadowSaveRefusesAttributeId()
    {
        $this->expectException(InvalidArgumentException::class);
        (new AttachmentTool())->saveShadow('1', '../838', 'x');
    }

    public function testChangeIdRefusesId()
    {
        $this->expectException(InvalidArgumentException::class);
        (new AttachmentTool())->changeID('1', '838.php', '839');
    }

    public function testDeleteAllRefusesEventPath()
    {
        $this->expectException(InvalidArgumentException::class);
        (new AttachmentTool())->deleteAll('1/../..');
    }
}
