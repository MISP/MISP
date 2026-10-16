<?php
require_once __DIR__ . '/../Lib/Tools/GalaxyMatrixLayout.php';

use PHPUnit\Framework\TestCase;

class GalaxyMatrixLayoutTest extends TestCase
{
    const ENTERPRISE = [
        'attack-Containers' => ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'stealth', 'defense-impairment', 'credential-access', 'discovery', 'lateral-movement', 'impact'],
        'attack-ESXi' => ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'stealth', 'defense-impairment', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'],
        'attack-Office-365' => ['initial-access', 'stealth', 'lateral-movement'],
        'attack-PRE' => ['reconnaissance', 'resource-development'],
        'mobile-attack-Android' => ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact', 'network-effects', 'remote-service-effects'],
        'pre-attack' => ['priority-definition-planning', 'target-selection'],
    ];

    public function testEnterpriseTabsArePlatformTabsWithPreFirst()
    {
        $this->assertSame(
            ['attack-PRE', 'attack-Containers', 'attack-ESXi', 'attack-Office-365'],
            GalaxyMatrixLayout::enterpriseTabs(self::ENTERPRISE + ['attack-enterprise' => []])
        );
    }

    public function testMergeKeepsEveryTabsRelativeOrder()
    {
        $tabs = GalaxyMatrixLayout::enterpriseTabs(self::ENTERPRISE);
        $columns = GalaxyMatrixLayout::mergeColumnOrders(array_map(function ($tab) {
            return self::ENTERPRISE[$tab];
        }, $tabs));
        $this->assertSame([
            'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
            'privilege-escalation', 'stealth', 'defense-impairment', 'credential-access', 'discovery',
            'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact',
        ], $columns);
    }

    public function testMergeSlotsAnotherDomainsColumnsByTheirNeighbours()
    {
        $columns = GalaxyMatrixLayout::mergeColumnOrders([
            ['initial-access', 'privilege-escalation', 'stealth', 'credential-access', 'impact'],
            ['initial-access', 'privilege-escalation', 'defense-evasion', 'credential-access', 'impact', 'network-effects'],
        ]);
        $this->assertSame(
            ['initial-access', 'privilege-escalation', 'stealth', 'defense-evasion', 'credential-access', 'impact', 'network-effects'],
            $columns
        );
    }

    public function testMergeSurvivesSequencesThatDisagree()
    {
        $columns = GalaxyMatrixLayout::mergeColumnOrders([['a', 'b', 'c'], ['c', 'a']]);
        $this->assertSame(['a', 'b', 'c'], $columns);
    }

    public function testMergeKeepsNumericColumnNames()
    {
        $this->assertSame(['2', '1'], GalaxyMatrixLayout::mergeColumnOrders([['2', '1']]));
    }
}
