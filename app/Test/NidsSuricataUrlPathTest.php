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
require_once __DIR__ . '/../Lib/Export/NidsSuricataExport.php';

class NidsSuricataUrlPathTest extends TestCase
{
    private function rule($value)
    {
        $item = [
            'Attribute' => ['id' => 5, 'type' => 'url', 'value' => $value, 'timestamp' => 1700000000],
            'AttributeTag' => [],
            'Event' => ['id' => 7, 'threat_level_id' => 2, 'uuid' => 'u', 'EventTag' => []],
        ];
        $export = new NidsSuricataExport();
        $export->handler($item, ['scope' => 'Attribute', 'user' => ['nids_sid' => 4000000]]);
        $this->assertCount(1, $export->rules);
        return $export->rules[0];
    }

    public function testHttpPathIsEscapedInContent()
    {
        $rule = $this->rule('http://evil.example/a";b|c');
        $this->assertStringContainsString('http.uri; content:"/a|22||3b|b|7c|c"; nocase;', $rule);
    }

    public function testOrdinaryHttpPathIsUnchanged()
    {
        $rule = $this->rule('http://evil.example/index.php');
        $this->assertStringContainsString(
            'http.header; content:"evil.example"; fast_pattern; nocase; http.uri; content:"/index.php"; nocase;',
            $rule
        );
    }
}
