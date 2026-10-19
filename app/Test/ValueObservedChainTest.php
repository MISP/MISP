<?php
/**
 * Value::observedFrom()/observedAt() and the recording date they end in,
 * and the self-sighting window that reads the same date.
 *
 * Pure PHPUnit, no CakePHP bootstrap and no database. The framework
 * classes the model touches are stubbed, each guarded so that a full-suite
 * run sharing one process keeps whichever stub loaded first.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $id = false;
        public $data = array();
        public $validationErrors = array();
    }
}

require_once __DIR__ . '/../Model/Value.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueExclusionTool.php';

use PHPUnit\Framework\TestCase;

class ValueObservedChainTest extends TestCase
{
    const RECORDED = 'CASE WHEN Attribute.created > 0'
        . ' AND Attribute.created <= Attribute.timestamp'
        . ' THEN Attribute.created ELSE Attribute.timestamp END';

    public function testTheChainsEndInTheRecordingDate()
    {
        $value = new Value();
        $this->assertSame(
            'COALESCE(FLOOR(Attribute.first_seen / 1000000),'
                . ' FLOOR(Attribute.last_seen / 1000000), '
                . self::RECORDED . ')',
            $value->observedFrom()
        );
        $this->assertSame(
            'COALESCE(FLOOR(Attribute.last_seen / 1000000),'
                . ' FLOOR(Attribute.first_seen / 1000000), '
                . self::RECORDED . ')',
            $value->observedAt()
        );
    }

    public function testTheRecordingDateTakesAnAlias()
    {
        $this->assertSame(
            str_replace('Attribute.', 'A.', self::RECORDED),
            Value::recordedAt('A')
        );
    }

    public function recordings()
    {
        return array(
            'created here, edited since' => array(1000, 5000, 1000),
            'created here, never edited' => array(1000, 1000, 1000),
            'pulled: the origin stamp is older' => array(9000, 5000, 5000),
            'from before 3.0' => array(0, 5000, 5000),
            'no creation key at all' => array(null, 5000, 5000),
        );
    }

    /**
     * @dataProvider recordings
     */
    public function testTheStampMatchesTheSql($created, $timestamp, $expected)
    {
        $row = array('timestamp' => $timestamp);
        if ($created !== null) {
            $row['created'] = $created;
        }
        $this->assertSame($expected, Value::recordedStamp($row));
    }

    private static function sighting($attributeId, $orgId, $at)
    {
        return array('Sighting' => array(
            'attribute_id' => $attributeId,
            'org_id' => $orgId,
            'date_sighting' => $at,
        ));
    }

    public function testASelfSightingIsTimedFromTheCreation()
    {
        $plan = array('rules' => array(
            ValueExclusionTool::SIGHTINGS_SELF => array('within_hours' => 1),
        ));
        $occurrences = array(
            // Created at 1000, edited a day later.
            7 => array('orgc_id' => 3, 'created' => 1000,
                'timestamp' => 1000 + 86400),
            // From before 3.0: only the edit is known.
            8 => array('orgc_id' => 3, 'created' => 0,
                'timestamp' => 1000 + 86400),
        );
        $result = (new ValueExclusionTool())->applyToSightings(
            array(
                self::sighting(7, 3, 1000 + 1800),
                self::sighting(8, 3, 1000 + 1800),
            ),
            $occurrences,
            $plan
        );
        $this->assertSame(1, $result['excluded']);
        $this->assertSame(
            8,
            $result['rows'][0]['Sighting']['attribute_id']
        );
    }
}
