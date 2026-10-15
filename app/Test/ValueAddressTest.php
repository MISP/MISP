<?php
/**
 * The address columns of analyst data and collection elements: which column a
 * target type selects, how the pair is normalised, and what validation lets
 * through.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        return vsprintf($singular, array_slice(func_get_args(), 1));
    }
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
if (!class_exists('Validation', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Validation.php';
}

require_once __DIR__ . '/../Model/AnalystData.php';
require_once __DIR__ . '/../Model/Relationship.php';
require_once __DIR__ . '/../Model/CollectionElement.php';

class ValueAddressRelationshipProbe extends Relationship
{
    public $data = [];
}

class ValueAddressElementProbe extends CollectionElement
{
    public $data = [];
}

class ValueAddressTest extends TestCase
{
    const UUID = '28635464-d6d0-499a-8467-47a06c447d63';

    const OTHER_UUID = 'bdfc376c-be54-44be-bc54-53cb08832a65';

    const ENDS = ['object', 'related_object', 'element'];

    // The model constructors need CakePHP; validAddress() only reads $data
    private static function probe($class)
    {
        return (new ReflectionClass($class))->newInstanceWithoutConstructor();
    }

    private static function hash($text = 'evil.example')
    {
        return hash('sha256', $text);
    }

    public function testTheTypeSelectsTheColumn()
    {
        foreach (self::ENDS as $end) {
            $this->assertSame($end . '_sha256', AnalystData::addressColumn('AttributeValue', $end));
            foreach (array_diff(AnalystData::valid_targets, AnalystData::SHA256_TARGETS) as $type) {
                $this->assertSame($end . '_uuid', AnalystData::addressColumn($type, $end), $type);
            }
            $this->assertSame($end . '_uuid', AnalystData::addressColumn('Unknown', $end));
            $this->assertSame($end . '_uuid', AnalystData::addressColumn(null, $end));
            $this->assertSame($end . '_uuid', AnalystData::addressColumn('attributevalue', $end));
        }
    }

    public function testCreateAddsMissingColumnsAndUpdateDoesNot()
    {
        $row = AnalystData::normaliseAddress(['object_type' => 'Event'], 'object', true);
        $this->assertArrayHasKey('object_uuid', $row);
        $this->assertArrayHasKey('object_sha256', $row);
        $this->assertNull($row['object_uuid']);
        $this->assertNull($row['object_sha256']);

        $row = AnalystData::normaliseAddress(['note' => 'x'], 'object', false);
        $this->assertSame(['note' => 'x'], $row);
    }

    public function testBlankBecomesNull()
    {
        foreach (self::ENDS as $end) {
            foreach ([true, false] as $creating) {
                $row = AnalystData::normaliseAddress([$end . '_uuid' => '', $end . '_sha256' => '  '], $end, $creating);
                $this->assertNull($row[$end . '_uuid']);
                $this->assertNull($row[$end . '_sha256']);
            }
        }
    }

    public function testHashIsTrimmedAndLowercasedButUuidIsLeftAlone()
    {
        $upper = strtoupper(self::UUID);
        $row = AnalystData::normaliseAddress([
            'related_object_uuid' => $upper,
            'related_object_sha256' => ' ' . strtoupper(self::hash()) . "\n",
        ], 'related_object', true);
        $this->assertSame($upper, $row['related_object_uuid']);
        $this->assertSame(self::hash(), $row['related_object_sha256']);
    }

    /**
     * Every type against every filling of the pair, on every end.
     *
     * @return array
     */
    public function pairings()
    {
        $hash = self::hash();
        $uuidTypes = array_merge(array_diff(AnalystData::valid_targets, AnalystData::SHA256_TARGETS), ['Unknown', null]);
        $cases = [];
        foreach (self::ENDS as $end) {
            foreach ($uuidTypes as $type) {
                $label = $end . ' ' . var_export($type, true);
                $cases["$label: uuid"] = [$end, $type, self::UUID, null, true, true];
                $cases["$label: nothing"] = [$end, $type, null, null, false, true];
                $cases["$label: hash only"] = [$end, $type, null, $hash, false, false];
                $cases["$label: both"] = [$end, $type, self::UUID, $hash, true, false];
                $cases["$label: malformed uuid"] = [$end, $type, 'not-a-uuid', null, false, true];
            }
            $label = $end . ' AttributeValue';
            $cases["$label: hash"] = [$end, 'AttributeValue', null, $hash, true, true];
            $cases["$label: nothing"] = [$end, 'AttributeValue', null, null, true, false];
            $cases["$label: uuid only"] = [$end, 'AttributeValue', self::UUID, null, false, false];
            $cases["$label: both"] = [$end, 'AttributeValue', self::UUID, $hash, false, true];
            $cases["$label: upper case"] = [$end, 'AttributeValue', null, strtoupper($hash), true, false];
            $cases["$label: 63 characters"] = [$end, 'AttributeValue', null, substr($hash, 1), true, false];
            $cases["$label: 65 characters"] = [$end, 'AttributeValue', null, $hash . 'a', true, false];
            $cases["$label: not hex"] = [$end, 'AttributeValue', null, str_repeat('g', 64), true, false];
            $cases["$label: a number"] = [$end, 'AttributeValue', null, 12345, true, false];
        }
        return $cases;
    }

    /**
     * @dataProvider pairings
     */
    public function testPairing($end, $type, $uuid, $sha256, $uuidOk, $sha256Ok)
    {
        $row = [$end . '_type' => $type, $end . '_uuid' => $uuid, $end . '_sha256' => $sha256];
        $this->assertSame($uuidOk, AnalystData::addressError($row, $end . '_uuid') === null, 'uuid column');
        $this->assertSame($sha256Ok, AnalystData::addressError($row, $end . '_sha256') === null, 'sha256 column');
    }

    public function testRelationshipEndsAreCheckedIndependently()
    {
        $relationship = self::probe(ValueAddressRelationshipProbe::class);
        $relationship->data['Relationship'] = [
            'object_type' => 'Attribute',
            'object_uuid' => self::UUID,
            'object_sha256' => null,
            'related_object_type' => 'AttributeValue',
            'related_object_uuid' => null,
            'related_object_sha256' => self::hash(),
        ];
        foreach (['object_uuid', 'object_sha256', 'related_object_uuid', 'related_object_sha256'] as $column) {
            $this->assertTrue($relationship->validAddress([$column => null]), $column);
        }

        $relationship->data['Relationship']['object_sha256'] = self::hash();
        $this->assertIsString($relationship->validAddress(['object_sha256' => null]));
        $this->assertTrue($relationship->validAddress(['related_object_sha256' => null]));
    }

    public function testElementCarriesNoHashForAUuidType()
    {
        $element = self::probe(ValueAddressElementProbe::class);
        $element->data['CollectionElement'] = [
            'element_type' => 'Event',
            'element_uuid' => self::UUID,
            'element_sha256' => self::hash(),
        ];
        $this->assertTrue($element->validAddress(['element_uuid' => null]));
        $this->assertIsString($element->validAddress(['element_sha256' => null]));
    }

    public function testSelfReferenceOnHashEnds()
    {
        $hash = self::hash();
        $this->assertTrue(Relationship::isSelfReference([
            'object_sha256' => $hash,
            'related_object_sha256' => ' ' . strtoupper($hash) . ' ',
        ]));
        $this->assertFalse(Relationship::isSelfReference([
            'object_sha256' => $hash,
            'related_object_sha256' => self::hash('other.example'),
        ]));
        $this->assertFalse(Relationship::isSelfReference([
            'object_uuid' => null,
            'object_sha256' => $hash,
            'related_object_uuid' => self::UUID,
            'related_object_sha256' => null,
        ]));
        $this->assertFalse(Relationship::isSelfReference([
            'object_uuid' => self::UUID,
            'object_sha256' => null,
            'related_object_uuid' => self::OTHER_UUID,
            'related_object_sha256' => null,
        ]));
    }
}
