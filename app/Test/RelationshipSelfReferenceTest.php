<?php
/**
 * Relationship::isSelfReference: when a relationship's two ends name the
 * same target.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }

        public static function import($type = null, $name = null, $parent = true)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}

require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Relationship.php';

class RelationshipSelfReferenceTest extends TestCase
{
    const A = '28635464-d6d0-499a-8467-47a06c447d63';

    const B = 'bdfc376c-be54-44be-bc54-53cb08832a65';

    public function testMissingEndsAreNotASelfReference()
    {
        $this->assertFalse(Relationship::isSelfReference([]));
        $this->assertFalse(Relationship::isSelfReference(['object_uuid' => null, 'related_object_uuid' => null]));
        $this->assertFalse(Relationship::isSelfReference(['object_uuid' => '', 'related_object_uuid' => '']));
        $this->assertFalse(Relationship::isSelfReference(['object_uuid' => self::A]));
        $this->assertFalse(Relationship::isSelfReference(['related_object_uuid' => self::A]));
    }

    public function testDifferentEndsAreNotASelfReference()
    {
        $this->assertFalse(Relationship::isSelfReference(['object_uuid' => self::A, 'related_object_uuid' => self::B]));
    }

    public function testSameEndIsASelfReference()
    {
        $this->assertTrue(Relationship::isSelfReference(['object_uuid' => self::A, 'related_object_uuid' => self::A]));
        $this->assertTrue(Relationship::isSelfReference([
            'object_uuid' => self::A,
            'related_object_uuid' => ' ' . strtoupper(self::A) . ' ',
        ]));
    }
}
