<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Export/BroExport.php';
if (!class_exists('Configure')) {
    class Configure
    {
        public static function read($key = null)
        {
            return $key === 'MISP.baseurl' ? 'http://misp.example' : null;
        }
    }
}

/**
 * Runs the real MispAttribute::__bro() body against a stub whose
 * fetchAttributes() returns only the Event fields that were asked for.
 */
class BroExportEventInfoTest extends TestCase
{
    private static function stubClass()
    {
        $name = 'BroQueryStubForEventInfo';
        if (!class_exists($name, false)) {
            $source = file_get_contents(__DIR__ . '/../Model/MispAttribute.php');
            $start = strpos($source, 'private function __bro(');
            $open = strpos($source, '{', $start);
            $depth = 0;
            for ($i = $open, $n = strlen($source); $i < $n; $i++) {
                if ($source[$i] === '{') {
                    $depth++;
                } elseif ($source[$i] === '}' && --$depth === 0) {
                    break;
                }
            }
            $method = substr($source, $start, $i - $start + 1);
            eval('class ' . $name . ' {
                public $Event;
                ' . $method . '
                public function fetchAttributes($user, $options)
                {
                    $row = array(
                        "Attribute" => array("type" => "domain", "value" => "evil.example", "value1" => "evil.example", "comment" => "c"),
                        "Event" => array()
                    );
                    $values = array("Event.id" => 1, "Event.uuid" => "u", "Event.orgc_id" => 2, "Event.info" => "Campaign X", "Event.threat_level_id" => 2);
                    foreach ($options["contain"]["Event"]["fields"] as $field) {
                        $row["Event"][substr($field, 6)] = $values[$field];
                    }
                    return array($row);
                }
            }');
        }
        return $name;
    }

    public function testDescriptionCarriesTheEventInfo()
    {
        $class = self::stubClass();
        $stub = new $class();
        $stub->Event = new stdClass();
        $stub->Event->Orgc = new class {
            public function find($type, $options)
            {
                return [2 => 'Org'];
            }
        };
        $method = new ReflectionMethod($class, '__bro');
        $method->setAccessible(true);
        $lines = $method->invoke($stub, [], [], 1, new BroExport(), 'MISP', false);
        $this->assertCount(1, $lines);
        $fields = explode("\t", $lines[0]);
        $this->assertSame('Intel::DOMAIN', $fields[1]);
        $this->assertSame('Campaign X. c', $fields[3]);
    }
}
