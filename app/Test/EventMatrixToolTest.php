<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/GalaxyMatrixLayout.php';
require_once __DIR__ . '/../Lib/Tools/EventOverview/EventMatrixTool.php';

use PHPUnit\Framework\TestCase;

class EventMatrixToolTest extends TestCase
{
    const ATTACK = [
        'id' => 36, 'uuid' => 'g-attack', 'name' => 'MITRE ATT&CK Techniques', 'type' => 'mitre-attack-pattern',
        'namespace' => 'mitre', 'icon' => 'map',
        'kill_chain_order' => [
            'attack-Windows' => ['initial-access', 'execution', 'exfiltration'],
            'attack-PRE' => ['reconnaissance'],
            'mobile-attack-Android' => ['initial-access', 'exfiltration', 'network-effects'],
        ],
    ];

    const FRAUD = [
        'id' => 5, 'uuid' => 'g-fraud', 'name' => 'attck4fraud', 'type' => 'financial-fraud',
        'namespace' => 'misp', 'icon' => 'money',
        'kill_chain_order' => ['fraud-tactics' => ['Initiation', 'Perform Fraud']],
    ];

    private function cluster(array $galaxy, $id, $value, $externalId, array $killChain)
    {
        return [
            'id' => $id, 'uuid' => 'c' . $id, 'value' => $value, 'tag_id' => 100 + $id,
            'tag_name' => 'misp-galaxy:' . $galaxy['type'] . '="' . $value . '"',
            'Galaxy' => $galaxy,
            'meta' => ['kill_chain' => $killChain] + ($externalId === null ? [] : ['external_id' => [$externalId]]),
        ];
    }

    private function hit(array $cluster, array $event = [], array $indicators = [])
    {
        return ['cluster' => $cluster, 'event' => $event, 'indicators' => $indicators];
    }

    private function tactics(array $galaxy)
    {
        $out = [];
        foreach ($galaxy['tactics'] as $tactic) {
            $out[$tactic['key']] = array_map(function ($group) {
                return $group['tid'] . ':' . $group['state'] . ':' . count($group['subs']);
            }, $tactic['groups']);
        }
        return $out;
    }

    public function testMatrixGalaxyNeedsAKillChainWithColumns()
    {
        $this->assertTrue(EventMatrixTool::isMatrixGalaxy(self::ATTACK));
        $this->assertTrue(EventMatrixTool::isMatrixGalaxy(['kill_chain_order' => '{"t":["a"]}']));
        $this->assertFalse(EventMatrixTool::isMatrixGalaxy(['kill_chain_order' => null]));
        $this->assertFalse(EventMatrixTool::isMatrixGalaxy(['kill_chain_order' => 'null']));
        $this->assertFalse(EventMatrixTool::isMatrixGalaxy(['kill_chain_order' => ['t' => []]]));
    }

    public function testTabsMergeIntoOneTacticOrderEnterpriseFirst()
    {
        $this->assertSame(
            ['reconnaissance', 'initial-access', 'execution', 'exfiltration', 'network-effects'],
            EventMatrixTool::tacticOrder(self::ATTACK)
        );
    }

    public function testOnlyActiveTechniquesByTacticWithSubTechniquesFolded()
    {
        $phishing = $this->cluster(self::ATTACK, 1, 'Phishing - T1566', 'T1566', ['attack-Windows:initial-access']);
        $link = $this->cluster(self::ATTACK, 2, 'Spearphishing Link - T1566.002', 'T1566.002', ['attack-Windows:initial-access']);
        $exfilMobile = $this->cluster(self::ATTACK, 3, 'Exfiltration Over C2 Channel - T1646', 'T1646', ['mobile-attack-Android:exfiltration']);
        $recon = $this->cluster(self::ATTACK, 4, 'Phishing for Information - T1598', 'T1598', ['attack-PRE:reconnaissance']);
        $galaxies = EventMatrixTool::compact([
            $this->hit($link, [13], [13 => 2]),
            ['loose' => [13 => 3]] + $this->hit($phishing, [], [13 => 4]),
            $this->hit($exfilMobile, [], [13 => 16]),
            $this->hit($recon, [13]),
        ], 13);

        $this->assertCount(1, $galaxies);
        $this->assertSame(4, $galaxies[0]['techniques']);
        $this->assertSame(2, $galaxies[0]['onEvent']);
        $this->assertSame([
            'reconnaissance' => ['T1598:event:0'],
            'initial-access' => ['T1566:event:1'],
            'exfiltration' => ['T1646:indicators:0'],
        ], $this->tactics($galaxies[0]));
        $phishingGroup = $galaxies[0]['tactics'][1]['groups'][0];
        $this->assertSame('Phishing', $phishingGroup['label']);
        $this->assertSame('indicators', $phishingGroup['own']['state']);
        $this->assertSame(4, $phishingGroup['own']['indicators']);
        $this->assertSame(3, $phishingGroup['own']['loose']);
        $this->assertSame(3, $phishingGroup['loose']);
        $this->assertSame('Spearphishing Link', $phishingGroup['subs'][0]['label']);
        $this->assertSame(6, $phishingGroup['indicators']);
    }

    public function testATechniqueInSeveralTacticsIsListedUnderEach()
    {
        $registry = $this->cluster(self::ATTACK, 5, 'Modify Registry - T1112', 'T1112', [
            'attack-Windows:execution', 'attack-Windows:exfiltration', 'attack-Linux:execution',
        ]);
        $galaxies = EventMatrixTool::compact([$this->hit($registry, [13])], 13);
        $this->assertSame(['execution' => ['T1112:event:0'], 'exfiltration' => ['T1112:event:0']], $this->tactics($galaxies[0]));
        $this->assertSame(1, $galaxies[0]['techniques']);
    }

    public function testAnOrphanSubTechniqueTakesItsParentsNameFromOutside()
    {
        $sub = $this->cluster(self::ATTACK, 6, 'JavaScript - T1059.007', 'T1059.007', ['attack-Windows:execution']);
        $hits = [$this->hit($sub, [13])];
        $this->assertSame([36 => ['T1059']], EventMatrixTool::missingParents($hits));
        $galaxies = EventMatrixTool::compact($hits, 13, [36 => ['T1059' => 'Command and Scripting Interpreter']]);
        $group = $galaxies[0]['tactics'][0]['groups'][0];
        $this->assertSame('T1059', $group['tid']);
        $this->assertSame('Command and Scripting Interpreter', $group['label']);
        $this->assertNull($group['own']);
        $this->assertSame('event', $group['state']);
    }

    public function testOriginsAndForeignInAnExtensionSet()
    {
        $own = $this->cluster(self::ATTACK, 7, 'Phishing - T1566', 'T1566', ['attack-Windows:initial-access']);
        $theirs = $this->cluster(self::ATTACK, 8, 'User Execution - T1204', 'T1204', ['attack-Windows:execution']);
        $shared = $this->cluster(self::ATTACK, 9, 'Exfiltration Over C2 Channel - T1041', 'T1041', ['attack-Windows:exfiltration']);
        $galaxies = EventMatrixTool::compact([
            $this->hit($own, [13]),
            $this->hit($theirs, [], [7 => 3]),
            $this->hit($shared, [7], [13 => 1]),
        ], 13);
        $byTid = [];
        foreach ($galaxies[0]['tactics'] as $tactic) {
            foreach ($tactic['groups'] as $group) {
                $byTid[$group['tid']] = $group;
            }
        }
        $this->assertFalse($byTid['T1566']['foreign']);
        $this->assertTrue($byTid['T1204']['foreign']);
        $this->assertSame([7], $byTid['T1204']['origins']);
        $this->assertFalse($byTid['T1041']['foreign']);
        $this->assertSame('event', $byTid['T1041']['state']);
        $this->assertSame([7, 13], $byTid['T1041']['origins']);
    }

    public function testAttackFirstThenByTechniqueCountAndNonMatrixClustersDropped()
    {
        $fraud1 = $this->cluster(self::FRAUD, 10, 'Phishing', null, ['fraud-tactics:Initiation']);
        $fraud2 = $this->cluster(self::FRAUD, 11, 'Account takeover', null, ['fraud-tactics:Perform Fraud']);
        $attack = $this->cluster(self::ATTACK, 12, 'Phishing - T1566', 'T1566', ['attack-Windows:initial-access']);
        $actor = $this->cluster(['id' => 1, 'type' => 'threat-actor', 'name' => 'Threat Actor', 'kill_chain_order' => null], 13, 'APT28', null, []);
        $noColumn = $this->cluster(self::ATTACK, 14, 'Odd - T9999', 'T9999', []);
        $galaxies = EventMatrixTool::compact([
            $this->hit($fraud1, [13]), $this->hit($fraud2, [13]), $this->hit($attack, [], [13 => 1]),
            $this->hit($actor, [13]), $this->hit($noColumn, [13]),
        ], 13);
        $this->assertSame(['mitre-attack-pattern', 'financial-fraud'], array_column($galaxies, 'type'));
        $this->assertSame(['Initiation' => [':event:0'], 'Perform Fraud' => [':event:0']], $this->tactics($galaxies[1]));
        $this->assertSame('Phishing', $galaxies[1]['tactics'][0]['groups'][0]['label']);
    }

    public function testNothingActiveIsNoGalaxy()
    {
        $attack = $this->cluster(self::ATTACK, 15, 'Phishing - T1566', 'T1566', ['attack-Windows:initial-access']);
        $this->assertSame([], EventMatrixTool::compact([$this->hit($attack, [], [13 => 0])], 13));
    }

    public function testAColumnTheTabDoesNotListIsPlacedByTheOtherTabs()
    {
        $galaxy = ['kill_chain_order' => [
            'attack-Windows' => ['initial-access', 'privilege-escalation', 'stealth', 'impact'],
            'mobile-attack-Android' => ['initial-access', 'privilege-escalation', 'defense-evasion', 'impact'],
        ]] + self::ATTACK;
        $impact = $this->cluster($galaxy, 20, 'Data Destruction - T1485', 'T1485', ['attack-Windows:impact']);
        $evasion = $this->cluster($galaxy, 21, 'Modify Registry - T1112', 'T1112', ['attack-Windows:defense-evasion']);
        $access = $this->cluster($galaxy, 22, 'Phishing - T1566', 'T1566', ['attack-Windows:initial-access']);
        $galaxies = EventMatrixTool::compact([
            $this->hit($impact, [13]), $this->hit($evasion, [13]), $this->hit($access, [13]),
        ], 13);
        $this->assertSame(['initial-access', 'defense-evasion', 'impact'], array_column($galaxies[0]['tactics'], 'key'));
    }

    public function testFullDrawsEveryTechniqueOfTheBusiestTabWithTheEventsStates()
    {
        $cell = function ($id, $value, $externalId) {
            return [
                'id' => $id, 'uuid' => 'c' . $id, 'value' => $value, 'external_id' => $externalId,
                'tag_name' => 'misp-galaxy:mitre-attack-pattern="' . $value . '"', 'default' => true,
            ];
        };
        $phishing = $cell(1, 'Phishing - T1566', 'T1566');
        $link = $cell(2, 'Spearphishing Link - T1566.002', 'T1566.002');
        $exploit = $cell(3, 'Exploit Public-Facing Application - T1190', 'T1190');
        $exec = $cell(4, 'User Execution - T1204', 'T1204');
        $mobile = $cell(5, 'Exfiltration Over C2 Channel - T1646', 'T1646');
        $skeleton = EventMatrixTool::slimSkeleton([
            'killChain' => [
                'attack-enterprise' => ['initial-access', 'execution', 'exfiltration'],
                'mobile-attack-Android' => ['initial-access', 'exfiltration'],
            ],
            'tabs' => [
                'attack-enterprise' => [
                    'execution' => [$exec],
                    'initial-access' => [$link, $exploit, $phishing, ['deleted' => true] + $cell(6, 'Gone - T1000', 'T1000')],
                    'exfiltration' => [],
                ],
                'mobile-attack-Android' => ['exfiltration' => [$mobile]],
            ],
        ]);
        $hits = [
            $this->hit($this->cluster(self::ATTACK, 2, 'Spearphishing Link - T1566.002', 'T1566.002', ['attack-Windows:initial-access']), [], [13 => 3]),
            $this->hit($this->cluster(self::ATTACK, 4, 'User Execution - T1204', 'T1204', ['attack-Windows:execution']), [13]),
        ];
        $full = EventMatrixTool::full($skeleton, self::ATTACK, $hits, 13);

        $this->assertSame('attack-enterprise', $full['tab']);
        $this->assertSame([['attack-enterprise', 'Enterprise', 2], ['mobile-attack-Android', 'Mobile · Android', 0]], array_map(function ($tab) {
            return [$tab['key'], $tab['label'], $tab['active']];
        }, $full['tabs']));
        $this->assertSame(['initial-access', 'execution'], array_column($full['columns'], 'key'));
        $access = $full['columns'][0];
        $this->assertSame(['Exploit Public-Facing Application', 'Phishing'], array_column($access['groups'], 'label'));
        $this->assertSame('idle', $access['groups'][0]['state']);
        $this->assertSame('indicators', $access['groups'][1]['state']);
        $this->assertSame('idle', $access['groups'][1]['own']['state']);
        $this->assertSame(3, $access['groups'][1]['subs'][0]['indicators']);
        $this->assertSame('event', $full['columns'][1]['groups'][0]['state']);

        $mobileTab = EventMatrixTool::full($skeleton, self::ATTACK, $hits, 13, 'mobile-attack-Android');
        $this->assertSame('mobile-attack-Android', $mobileTab['tab']);
        $this->assertSame('idle', $mobileTab['columns'][0]['groups'][0]['state']);
        $this->assertSame('attack-enterprise', EventMatrixTool::full($skeleton, self::ATTACK, $hits, 13, 'nope')['tab']);
    }

    public function testUsageMarksTheTechniquesEventsCarryWithTheirEventCount()
    {
        $cell = function ($id, $value, $externalId) {
            return [
                'id' => $id, 'uuid' => 'c' . $id, 'value' => $value, 'external_id' => $externalId,
                'tag_name' => 'misp-galaxy:mitre-attack-pattern="' . $value . '"', 'default' => true,
            ];
        };
        $phishing = $cell(1, 'Phishing - T1566', 'T1566');
        $exploit = $cell(3, 'Exploit Public-Facing Application - T1190', 'T1190');
        $mobile = $cell(5, 'Exfiltration Over C2 Channel - T1646', 'T1646');
        $skeleton = EventMatrixTool::slimSkeleton([
            'killChain' => [
                'attack-enterprise' => ['initial-access'],
                'mobile-attack-Android' => ['exfiltration'],
            ],
            'tabs' => [
                'attack-enterprise' => ['initial-access' => [$exploit, $phishing]],
                'mobile-attack-Android' => ['exfiltration' => [$mobile]],
            ],
        ]);
        $full = EventMatrixTool::usage($skeleton, self::ATTACK, [$mobile['tag_name'] => 7]);

        $this->assertSame('mobile-attack-Android', $full['tab']);
        $this->assertSame([0, 1], array_column($full['tabs'], 'active'));
        $used = $full['columns'][0]['groups'][0];
        $this->assertSame('event', $used['state']);
        $this->assertTrue($used['own']['onEvent']);
        $this->assertSame(7, $used['own']['events']);

        $enterprise = EventMatrixTool::usage($skeleton, self::ATTACK, [$mobile['tag_name'] => 7], 'attack-enterprise');
        $this->assertSame(['idle', 'idle'], array_column($enterprise['columns'][0]['groups'], 'state'));
        $this->assertSame(0, $enterprise['columns'][0]['groups'][0]['own']['events']);
    }

    public function testTabLabels()
    {
        $this->assertSame('ICS · Field Controller/RTU/PLC/IED', EventMatrixTool::tabLabel('ics-attack-Field-Controller/RTU/PLC/IED', 'mitre-attack-pattern'));
        $this->assertSame('ICS', EventMatrixTool::tabLabel('ics-attack', 'mitre-attack-pattern'));
        $this->assertSame('Network Devices', EventMatrixTool::tabLabel('attack-Network-Devices', 'mitre-attack-pattern'));
        $this->assertSame('Fraud Tactics', EventMatrixTool::tabLabel('fraud-tactics', 'financial-fraud'));
    }

    public function testGroupColumnFoldsSubTechniquesAndKeepsLegacyCellsApart()
    {
        $groups = GalaxyMatrixLayout::groupColumn([
            ['value' => 'Spearphishing Link - T1566.002', 'external_id' => 'T1566.002'],
            ['value' => 'Phishing - T1566', 'external_id' => 'T1566'],
            ['value' => 'Legacy', 'external_id' => ''],
            ['value' => 'Pre - PRE-T1001', 'external_id' => 'PRE-T1001'],
        ]);
        $this->assertSame(['T1566', '_Legacy', 'PRE-T1001'], array_keys($groups));
        $this->assertSame('Phishing', $groups['T1566']['label']);
        $this->assertSame('Spearphishing Link', $groups['T1566']['subs'][0]['label']);
        $this->assertSame('Pre', $groups['PRE-T1001']['label']);
        $this->assertSame('T1059', GalaxyMatrixLayout::groupLabel(['key' => 'T1059', 'label' => null], []));
    }
}
