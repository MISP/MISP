<?php
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function reset()
        {
            self::$values = array();
        }
    }
}

require_once __DIR__ . '/../Lib/Export/HostsExport.php';
require_once __DIR__ . '/../Lib/Export/RPZExport.php';

use PHPUnit\Framework\TestCase;

class HostsRpzExportParamsTest extends TestCase
{
    private const SETTINGS = [
        'policy' => 1, 'walled_garden' => '127.0.0.1', 'serial' => '$date00', 'refresh' => '2h',
        'retry' => '30m', 'expiry' => '30d', 'minimum_ttl' => '1h', 'ttl' => '1w',
        'ns' => 'localhost.', 'ns_alt' => '', 'email' => 'root.localhost',
    ];

    protected function setUp(): void
    {
        foreach (self::SETTINGS as $k => $v) {
            Configure::write('Plugin.RPZ_' . $k, $v);
        }
    }

    private function hosts($filters)
    {
        $export = new HostsExport();
        $export->header(['filters' => $filters]);
        return $export->handler(['Attribute' => ['type' => 'domain', 'value' => 'example.com']], ['scope' => 'Attribute']);
    }

    public function testHostsEventScopeWritesOneLinePerDomain()
    {
        $export = new HostsExport();
        $export->header(['filters' => ['ip_address' => '127.0.0.1']]);
        $event = ['Attribute' => [
            ['type' => 'domain', 'value' => 'a.example'],
            ['type' => 'domain', 'value' => 'b.example'],
            ['type' => 'domain', 'value' => 'a.example'],
        ]];
        $this->assertSame("127.0.0.1 a.example\n127.0.0.1 b.example\n", $export->handler($event, ['scope' => 'Event']));
        $this->assertSame('', $export->handler(['Attribute' => []], ['scope' => 'Event']));
    }

    private function rpz($filters, $items = [['type' => 'domain', 'value' => 'example.com']])
    {
        $export = new RPZExport();
        $export->header(['filters' => $filters]);
        foreach ($items as $item) {
            $export->handler(['Attribute' => $item], ['scope' => 'Attribute']);
        }
        return $export->footer();
    }

    public function testHostsIpAddress()
    {
        $this->assertSame("0.0.0.0 example.com\n", $this->hosts([]));
        $this->assertSame("127.0.0.1 example.com\n", $this->hosts(['ip_address' => '127.0.0.1']));
        $this->assertSame("::1 example.com\n", $this->hosts(['ip_address' => '::1']));
        foreach (["1.2.3.4\n9.9.9.9 evil.example", '1.2.3.4 evil', 'abc', ['1.2.3.4']] as $bad) {
            $this->assertSame("0.0.0.0 example.com\n", $this->hosts(['ip_address' => $bad]));
        }
    }

    public function testRpzDefaultOutput()
    {
        $out = $this->rpz([]);
        $this->assertStringContainsString('$TTL 1w;', $out);
        $this->assertStringContainsString('SOA localhost. root.localhost (' . date('Ymd') . '00 2h 30m 30d 1h)', $out);
        $this->assertStringContainsString("example.com CNAME .\n", $out);
    }

    public function testRpzValidRequestValuesAreUsed()
    {
        $out = $this->rpz([
            'ns' => 'ns1.example.org.', 'ns_alt' => 'ns2.example.org', 'email' => 'hostmaster.example.org',
            'serial' => '2024010101', 'refresh' => '3600', 'retry' => '15m', 'expiry' => '2w',
            'minimum_ttl' => '300', 'ttl' => '1d',
        ]);
        $this->assertStringContainsString('$TTL 1d;', $out);
        $this->assertStringContainsString('SOA ns1.example.org. hostmaster.example.org (2024010101 3600 15m 2w 300)', $out);
        $this->assertStringContainsString("NS ns2.example.org\n", $out);
    }

    public function testRpzLocalDataWalledGarden()
    {
        $out = $this->rpz(['policy' => 'Local-Data', 'walled_garden' => 'wall.example.org.']);
        $this->assertStringContainsString("example.com CNAME wall.example.org.\n", $out);
        $out = $this->rpz(['policy' => 'Local-Data', 'walled_garden' => "x.\nevil.example CNAME ."]);
        $this->assertStringContainsString("example.com CNAME 127.0.0.1\n", $out);
        $this->assertStringNotContainsString('evil', $out);
    }

    public function testRpzUnsafeRequestValuesAreIgnored()
    {
        $bad = "x\nevil.example. CNAME .";
        $out = $this->rpz([
            'ns' => $bad, 'ns_alt' => $bad, 'email' => "a b", 'serial' => "1 ) \n$bad",
            'refresh' => "1\n$bad", 'retry' => '1h; x', 'expiry' => '-5', 'minimum_ttl' => ['1'], 'ttl' => "1w\n",
        ]);
        $this->assertStringNotContainsString('evil', $out);
        $this->assertStringContainsString('$TTL 1w;', $out);
        $this->assertStringContainsString('SOA localhost. root.localhost (' . date('Ymd') . '00 2h 30m 30d 1h)', $out);
        $this->assertStringNotContainsString('NS ' . "\n", $out);
    }
}
