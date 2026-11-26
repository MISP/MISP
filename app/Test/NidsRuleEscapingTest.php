<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';
if (!class_exists('Configure')) {
    class Configure
    {
        public static function read($key = null)
        {
            return $key === 'MISP.baseurl' ? 'http://misp.example' : null;
        }
    }
}
if (!class_exists('App')) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Export/NidsExport.php';
require_once __DIR__ . '/../Lib/Export/NidsSnortExport.php';
require_once __DIR__ . '/../Lib/Export/NidsSuricataExport.php';

class NidsRuleEscapingTest extends TestCase
{
    private const NASTY = "x\"; sid:1; \\ a,b;\r\nalert ip any any -> any any (msg:\"y";

    private function rules($class, $tagNames, $value = '1.2.3.4')
    {
        $tags = [];
        foreach ($tagNames as $name) {
            $tags[] = ['Tag' => ['name' => $name]];
        }
        $item = [
            'Attribute' => [
                'id' => 5, 'type' => 'ip-dst', 'value' => $value, 'timestamp' => 1700000000,
            ],
            'AttributeTag' => $tags,
            'Event' => [
                'id' => 7, 'threat_level_id' => 2, 'uuid' => '11111111-1111-1111-1111-111111111111',
                'EventTag' => [],
            ],
        ];
        $export = new $class();
        $export->handler($item, ['scope' => 'Attribute', 'user' => ['nids_sid' => 4000000]]);
        return $export->rules;
    }

    private function options($rule)
    {
        $this->assertSame(1, preg_match('/\((.*)\)\s*$/', $rule, $m));
        // split on semicolons that are not escaped
        return preg_split('/(?<!\\\\);\s*/', trim($m[1]), -1, PREG_SPLIT_NO_EMPTY);
    }

    public function testSnortMsgStaysOneOption()
    {
        $rules = $this->rules('NidsSnortExport', [self::NASTY]);
        $this->assertCount(1, $rules);
        $this->assertStringNotContainsString("\n", $rules[0]);
        $this->assertStringNotContainsString("\r", $rules[0]);
        $options = $this->options($rules[0]);
        $this->assertCount(1, preg_grep('/^msg:/', $options));
        $this->assertCount(1, preg_grep('/^sid:/', $options));
        $this->assertSame('msg: "MISP e7 [x\\"\; sid:1\; \\\\ a,b\;__alert ip any any -> any any (msg:\\"y] Outgoing To IP: 1.2.3.4"', $options[0]);
    }

    public function testSnortOrdinaryTagsKeepTheirText()
    {
        $rules = $this->rules('NidsSnortExport', ['misp-galaxy:threat-actor="Sofacy"', 'tlp:green']);
        $this->assertStringContainsString(
            'msg: "MISP e7 [misp-galaxy:threat-actor=\\"Sofacy\\",tlp:green] Outgoing To IP: 1.2.3.4";',
            $rules[0]
        );
    }

    public function testSnortPercentInTagDoesNotBreakTheFormat()
    {
        $rules = $this->rules('NidsSnortExport', ['a%sb%d']);
        $this->assertStringContainsString('[a%sb%d]', $rules[0]);
    }

    public function testSuricataMetadataHasNoExtraSeparators()
    {
        $rules = $this->rules('NidsSuricataExport', [self::NASTY, 'ns:key="a;b,c"'], "v\",;\\\n x");
        $this->assertCount(1, $rules);
        $this->assertSame(1, preg_match('/metadata:([^;]*);\)\s*$/', $rules[0], $m));
        $entries = explode(',', $m[1]);
        $this->assertCount(6, $entries);
        $this->assertStringNotContainsString('"', $m[1]);
        $this->assertStringNotContainsString('\\', $m[1]);
        $this->assertStringNotContainsString("\n", $m[1]);
        $this->assertSame('misp_ioc v______x', array_values(preg_grep('/^misp_ioc/', $entries))[0]);
    }

    public function testSuricataStructureHoldsWithHostileTags()
    {
        $rules = $this->rules('NidsSuricataExport', [self::NASTY]);
        $this->assertCount(1, $rules);
        $this->assertStringNotContainsString("\n", $rules[0]);
        $options = $this->options($rules[0]);
        $this->assertCount(1, preg_grep('/^msg:/', $options));
        $this->assertCount(1, preg_grep('/^sid:/', $options));
        $this->assertCount(1, preg_grep('/^metadata:/', $options));
    }

    public function testSuricataOrdinaryMetadataIsUnchanged()
    {
        $rules = $this->rules('NidsSuricataExport', ['tlp:green', 'misp-galaxy:threat-actor="Some Actor"', 'plain tag'], 'a b');
        $this->assertStringContainsString(
            'metadata:tlp green,misp-galaxy:threat-actor Some_Actor,misp-tag plain_tag,'
            . 'misp_event_uuid 11111111-1111-1111-1111-111111111111,misp_ioc a_b,',
            $rules[0]
        );
    }

    private function typed($class, $type, $value)
    {
        $item = [
            'Attribute' => ['id' => 5, 'type' => $type, 'value' => $value, 'timestamp' => 1700000000],
            'AttributeTag' => [],
            'Event' => ['id' => 7, 'threat_level_id' => 2, 'uuid' => 'u', 'EventTag' => []],
        ];
        $export = new $class();
        $export->handler($item, ['scope' => 'Attribute', 'user' => ['nids_sid' => 4000000]]);
        return $export->rules;
    }

    public function testFreeTextValuesCannotEndMsg()
    {
        $value = "Mozilla\"; sid:1; x\x01alert ip any any -> any any (msg:\"y";
        foreach (['NidsSnortExport', 'NidsSuricataExport'] as $class) {
            $rules = $this->typed($class, 'ip-dst', $value);
            $this->assertCount(1, $rules, $class);
            $options = $this->options($rules[0]);
            $this->assertCount(1, preg_grep('/^msg:/', $options), $class);
            $this->assertCount(1, preg_grep('/^sid:/', $options), $class);
            $this->assertStringContainsString('Outgoing To IP', $options[0]);
        }
    }

    public function testLineBreaksInValuesNeverReachMsg()
    {
        foreach (['NidsSnortExport', 'NidsSuricataExport'] as $class) {
            $rules = $this->typed($class, 'user-agent', "a\r\nb");
            $this->assertSame(1, preg_match('/\(msg: "([^"]*)";/', $rules[0], $m), $class);
            $this->assertSame('a|0d||0a|b', substr($m[1], -10));
        }
    }

    public function testPercentInValueStaysSingle()
    {
        foreach (['NidsSnortExport', 'NidsSuricataExport'] as $class) {
            $rules = $this->typed($class, 'user-agent', 'a%b%%c');
            $this->assertStringContainsString('User-Agent', $rules[0]);
            $this->assertStringContainsString('a%b%%c"', $rules[0], $class);
        }
    }

    public function testLineBreaksInContentAreHexEncoded()
    {
        foreach (['NidsSnortExport', 'NidsSuricataExport'] as $class) {
            $rules = $this->typed($class, 'user-agent', "a\r\nb|c\x7f");
            $this->assertCount(1, $rules, $class);
            $this->assertStringNotContainsString("\n", $rules[0], $class);
            $this->assertStringNotContainsString("\r", $rules[0], $class);
            $this->assertStringContainsString('content:"a|0d||0a|b|7c|c|7f|"', $rules[0], $class);
        }
    }
}
