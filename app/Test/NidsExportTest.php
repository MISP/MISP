<?php
/**
 * NIDS export dispatch tests.
 *
 * Pure PHPUnit, like the other tests under app/Test/: no CakePHP
 * bootstrap, no DB. The export classes only reach the framework through
 * App::uses(), Configure::read() and CakeLog, all stubbed below before
 * the classes are loaded.
 *
 * NidsSuricataExport used to carry its own copy of the attribute type
 * dispatch of NidsExport::export(), so the seven types it adds could
 * only be reached through a duplicate of the whole switch. These tests
 * pin the shared dispatch and the rules both exports build with it.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function reset()
        {
            self::$values = array();
        }
    }
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static function notice($message)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Export/NidsExport.php';
require_once __DIR__ . '/../Lib/Export/NidsSnortExport.php';
require_once __DIR__ . '/../Lib/Export/NidsSuricataExport.php';

class NidsExportTest extends TestCase
{
    protected function setUp(): void
    {
        Configure::write('MISP.baseurl', 'https://misp.test');
    }

    // -------- dispatch --------

    public function testSuricataExportUsesTheDispatchOfNidsExport(): void
    {
        $export = new ReflectionMethod('NidsSuricataExport', 'export');
        $this->assertSame('NidsExport', $export->getDeclaringClass()->getName());
    }

    public function testSuricataExportHandlesEveryTypeOfTheBaseExport(): void
    {
        $base = $this->attributeRules(new NidsSnortExport());
        $suricata = $this->attributeRules(new NidsSuricataExport());
        $this->assertSame($base, array_intersect_key($suricata, $base));
    }

    public function testSuricataExportAddsItsOwnTypes(): void
    {
        $suricata = $this->attributeRules(new NidsSuricataExport());
        $this->assertSame('cookieRule', $suricata['cookie']);
        $this->assertSame('fileRule', $suricata['malware-sample']);
        $this->assertSame('patternInFileRule', $suricata['pattern-in-file']);
        $this->assertArrayNotHasKey('cookie', $this->attributeRules(new NidsSnortExport()));
    }

    // -------- rules --------

    public function testSnortIpDstRule(): void
    {
        $rules = $this->rules(new NidsSnortExport(), array('type' => 'ip-dst', 'value' => '1.2.3.4'));
        $this->assertSame(
            array('alert ip $HOME_NET any -> 1.2.3.4 any (msg: "MISP e42 [malware,tlp:white] Outgoing To IP: 1.2.3.4"; flow:not_established,to_server; flowbits:isnotset,outbound_ioc; flowbits:set,outbound_ioc;  classtype:bad-unknown; sid:5011; rev:1; priority:3; reference:url,https://misp.test/events/view/42;) '),
            $rules
        );
    }

    public function testSnortEmailBuildsASourceAndADestinationRule(): void
    {
        $rules = $this->rules(new NidsSnortExport(), array('type' => 'email', 'value' => 'a@b.com'));
        $this->assertCount(2, $rules);
        $this->assertStringContainsString('Source Email Address: a@b.com', $rules[0]);
        $this->assertStringContainsString('sid:5011;', $rules[0]);
        $this->assertStringContainsString('Destination Email Address: a@b.com', $rules[1]);
        $this->assertStringContainsString('sid:5012;', $rules[1]);
    }

    public function testSnortAttributeIsRewrittenInsteadOfRendered(): void
    {
        $rules = $this->rules(new NidsSnortExport(), array(
            'type' => 'snort',
            'value' => 'alert tcp any any -> any any (msg:"legacy"; sid:1; rev:9;)'
        ));
        $this->assertSame(
            array('alert tcp any any -> any any (msg: "MISP e42 [malware,tlp:white] snort-rule | legacy"; sid:5011; rev:1; classtype:bad-unknown;reference:url,https://misp.test/events/view/42;)'),
            $rules
        );
    }

    public function testSnortObjectRule(): void
    {
        $export = new NidsSnortExport();
        $export->handler(array(
            'Attribute' => array('id' => 1, 'name' => 'network-connection', 'Attribute' => array(
                array('object_relation' => 'ip-src', 'value' => '1.1.1.1'),
                array('object_relation' => 'ip-dst', 'value' => '2.2.2.2'),
                array('object_relation' => 'layer4-protocol', 'value' => 'tcp'),
                array('object_relation' => 'dst-port', 'value' => '53'),
            )),
            'AttributeTag' => array(),
            'Event' => array('id' => 42, 'uuid' => self::EVENT_UUID, 'threat_level_id' => 3),
        ), array('scope' => 'Attribute', 'user' => array('nids_sid' => 5000)));
        $this->assertCount(1, $export->rules);
        $this->assertStringContainsString('Network connection between 1.1.1.1 and 2.2.2.2', $export->rules[0]);
    }

    public function testSuricataDomainUsesTheSuricataRules(): void
    {
        $rules = $this->rules(new NidsSuricataExport(), array('type' => 'domain', 'value' => 'evil.com'));
        $this->assertCount(3, $rules);
        $this->assertStringContainsString('alert dns any any -> any any (msg: "MISP e42 Domain evil.com"; dns.query; content:"evil.com"; startswith; endswith;', $rules[0]);
        $this->assertStringContainsString('metadata:misp-tag malware,tlp white,misp_event_uuid ' . self::EVENT_UUID . ',misp_ioc evil.com,created_at 2023_11_14,', $rules[0]);
        $this->assertStringContainsString('http.host', $rules[1]);
        $this->assertStringContainsString('tls.sni', $rules[2]);
    }

    public function testSuricataOnlyTypesAreDispatched(): void
    {
        $rules = $this->rules(new NidsSuricataExport(), array('type' => 'cookie', 'value' => 'sess=1'));
        $this->assertCount(1, $rules);
        $this->assertStringContainsString('http.cookie; content:"sess=1"; nocase;', $rules[0]);

        $rules = $this->rules(new NidsSuricataExport(), array('type' => 'filename', 'value' => 'bad.exe'));
        $this->assertCount(1, $rules);
        $this->assertStringContainsString('Filename bad.exe', $rules[0]);

        $rules = $this->rules(new NidsSuricataExport(), array('type' => 'filename-pattern', 'value' => 'ba.*'));
        $this->assertCount(1, $rules);
        $this->assertStringContainsString('file.name; pcre:', $rules[0]);
    }

    public function testUnsupportedTypeBuildsNoRule(): void
    {
        $this->assertSame(array(), $this->rules(new NidsSnortExport(), array('type' => 'btc', 'value' => 'x')));
        $this->assertSame(array(), $this->rules(new NidsSuricataExport(), array('type' => 'btc', 'value' => 'x')));
    }

    // -------- helpers --------

    const EVENT_UUID = '5b3c0f2a-0000-4000-8000-000000000000';

    private function rules($export, array $attribute)
    {
        $export->handler(array(
            'Attribute' => $attribute + array('id' => 1, 'timestamp' => 1700000000),
            'AttributeTag' => array(array('Tag' => array('name' => 'malware'))),
            'Event' => array(
                'id' => 42,
                'uuid' => self::EVENT_UUID,
                'threat_level_id' => 3,
                'EventTag' => array(array('Tag' => array('name' => 'tlp:white'))),
            ),
        ), array('scope' => 'Attribute', 'user' => array('nids_sid' => 5000)));
        return $export->rules;
    }

    private function attributeRules($export)
    {
        $method = new ReflectionMethod(get_class($export), 'attributeRules');
        $method->setAccessible(true);
        return $method->invoke($export);
    }
}
