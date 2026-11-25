<?php
require_once __DIR__ . '/../Lib/Export/NetfilterExport.php';

use PHPUnit\Framework\TestCase;

class NetfilterExportTest extends TestCase
{
    private function attr($type, $value)
    {
        return ['type' => $type, 'value' => $value];
    }

    private function exportOne($scope, $data, $filters = [])
    {
        $export = new NetfilterExport();
        return $export->handler($data, ['scope' => $scope, 'filters' => $filters]);
    }

    public function testDefaultActionIsDrop()
    {
        $out = $this->exportOne('Attribute', ['Attribute' => $this->attr('ip-dst', '192.0.2.1')]);
        $this->assertSame("iptables -A INPUT -s 192.0.2.1 -j DROP\n", $out);
    }

    public function testAllowedActionsAreUsed()
    {
        foreach (['DROP', 'REJECT', 'ACCEPT', 'LOG'] as $action) {
            $out = $this->exportOne('Attribute', ['Attribute' => $this->attr('ip-dst', '192.0.2.1')], ['netfilter_action' => $action]);
            $this->assertSame("iptables -A INPUT -s 192.0.2.1 -j $action\n", $out);
        }
    }

    public function testUnsafeActionFallsBackToDefault()
    {
        foreach (["DROP\nrm -rf /", 'DROP; id', 'drop', 'MARK --set-mark 1', ['DROP']] as $action) {
            foreach (['Attribute' => ['Attribute' => $this->attr('ip-dst', '192.0.2.1')], 'Event' => ['Attribute' => [$this->attr('ip-dst', '192.0.2.1')]]] as $scope => $data) {
                $out = $this->exportOne($scope, $data, ['netfilter_action' => $action]);
                $this->assertSame("iptables -A INPUT -s 192.0.2.1 -j DROP\n", $out);
            }
        }
    }

    public function testEventScopeEmitsOneRulePerMatchingAttribute()
    {
        $data = ['Attribute' => [
            $this->attr('ip-src', '192.0.2.1'),
            $this->attr('md5', 'd41d8cd98f00b204e9800998ecf8427e'),
            $this->attr('domain|ip', 'example.com|192.0.2.2'),
            $this->attr('ip-dst|port', '192.0.2.3|80'),
        ]];
        $out = $this->exportOne('Event', $data, ['netfilter_action' => 'REJECT']);
        $this->assertSame(
            "iptables -A INPUT -s 192.0.2.1 -j REJECT\n" .
            "iptables -A INPUT -s 192.0.2.2 -j REJECT\n" .
            "iptables -A INPUT -s 192.0.2.3 -j REJECT\n",
            $out
        );
    }
}
