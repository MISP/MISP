<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueLabelPriority.php';
require_once __DIR__
    . '/../Lib/Tools/ValueIntelligence/ValueIntelligenceBuckets.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueStatsTool.php';
require_once __DIR__ . '/../Lib/Tools/GalaxyCategory.php';
require_once __DIR__ . '/../Lib/Tools/EventOverview/EventContextTool.php';
require_once __DIR__ . '/../Lib/Tools/EventOverview/EventOverviewTool.php';

use PHPUnit\Framework\TestCase;

class EventOverviewToolTest extends TestCase
{
    protected function setUp(): void
    {
        GalaxyCategory::prime([
            'threat-actor' => ['named-threat', 'actor'],
            'mitre-attack-pattern' => ['technique', 'attack-pattern'],
            'mitre-course-of-action' => ['defensive', 'course-of-action'],
            'disarm-techniques' => ['technique', 'technique'],
            'cyfun-control-catalogue-2023' => ['defensive', 'control'],
        ]);
    }

    protected function tearDown(): void
    {
        GalaxyCategory::forget();
    }

    private function eventTag($id, $name, array $extra = [])
    {
        return ['id' => 1000 + $id, 'local' => 0, 'Tag' => $extra + [
            'id' => $id, 'name' => $name, 'is_galaxy' => 0, 'hide_tag' => 0, 'colour' => '#000000',
        ]];
    }

    private function cluster($tagId, $value, $type)
    {
        return ['tag_id' => $tagId, 'value' => $value, 'Galaxy' => ['type' => $type, 'name' => $type]];
    }

    private function profile(array $context = [], array $galaxies = [])
    {
        return ['parameters' => ['context' => $context, 'galaxies' => $galaxies]];
    }

    private function keys(array $items)
    {
        return array_map(function ($item) {
            return $item['kind'] . ':' . $item['level'] . ':' . ($item['name'] ?? $item['key']);
        }, $items);
    }

    public function testMarkingsDefaultToTlpAndPap(): void
    {
        $this->assertSame(['tlp', 'pap'], ValueLabelPriority::markings($this->profile()));
        $this->assertSame(['tlp', 'pap'], ValueLabelPriority::markings(null));
    }

    public function testMarkingsAreLowercasedAndDeduplicated(): void
    {
        $profile = $this->profile(['markings' => ['NATO', ' tlp ', 'nato', '', 3]]);
        $this->assertSame(['nato', 'tlp', '3'], ValueLabelPriority::markings($profile));
    }

    public function testAnEmptyMarkingListMeansNone(): void
    {
        $this->assertSame([], ValueLabelPriority::markings($this->profile(['markings' => []])));
    }

    public function testRowsSortLabelsIntoTheirQuestion(): void
    {
        $tags = [
            $this->eventTag(1, 'tlp:amber'),
            $this->eventTag(2, 'PAP:AMBER'),
            $this->eventTag(3, 'circl:incident-classification="phishing"'),
            $this->eventTag(4, 'misp-galaxy:mitre-attack-pattern="Malicious File - T1204.002"', ['is_galaxy' => 1]),
            $this->eventTag(5, 'misp-galaxy:threat-actor="APT29"', ['is_galaxy' => 1]),
            $this->eventTag(6, 'misp-galaxy:sector="Finance"', ['is_galaxy' => 1]),
        ];
        $clusters = [
            $this->cluster(4, 'Malicious File - T1204.002', 'mitre-attack-pattern'),
            $this->cluster(5, 'APT29', 'threat-actor'),
            $this->cluster(6, 'Finance', 'sector'),
        ];
        $rows = EventContextTool::rows($tags, $clusters, null, [], [], $this->profile());

        $this->assertSame(['tag:event:tlp:amber', 'tag:event:PAP:AMBER'], $this->keys($rows['markings']));
        $this->assertSame(['cluster:event:APT29'], $this->keys($rows['attribution']));
        $this->assertSame(['cluster:event:Malicious File - T1204.002'], $this->keys($rows['behaviour']));
        $this->assertSame('T1204.002', $rows['behaviour'][0]['technique']);
        $this->assertSame(['tag:event:circl:incident-classification="phishing"'], $this->keys($rows['classification']));
        $this->assertSame(['cluster:event:Finance'], $this->keys($rows['clusters']));
    }

    public function testOnlyAttackPatternsAndCoursesOfActionGetTheirOwnRows(): void
    {
        $clusters = [
            $this->cluster(1, 'Malicious File - T1204.002', 'mitre-attack-pattern'),
            $this->cluster(2, 'Create Clickbait', 'disarm-techniques'),
            $this->cluster(3, 'User Training - M1017', 'mitre-course-of-action'),
            $this->cluster(4, 'ID.AM-1', 'cyfun-control-catalogue-2023'),
            $this->cluster(5, 'Legacy - T1566', 'stix-2.1-attack-pattern'),
        ];
        $rows = EventContextTool::rows([], $clusters, null, [], [], $this->profile());

        $this->assertSame(
            ['cluster:event:Malicious File - T1204.002', 'cluster:event:Legacy - T1566'],
            $this->keys($rows['behaviour'])
        );
        $this->assertSame(['cluster:event:User Training - M1017'], $this->keys($rows['mitigation']));
        $this->assertSame(
            ['cluster:event:Create Clickbait', 'cluster:event:ID.AM-1'],
            $this->keys($rows['clusters'])
        );
    }

    public function testBehaviourSplitsByParentGalaxyLargestFirst(): void
    {
        $mobile = ['id' => 7, 'type' => 'mitre-mobile-attack-pattern', 'name' => 'Mobile Attack - Attack Pattern'];
        $enterprise = ['id' => 3, 'type' => 'mitre-attack-pattern', 'name' => 'Attack Pattern'];
        $clusters = [
            ['tag_id' => 1, 'value' => 'Input Capture - T1417', 'Galaxy' => $mobile],
            ['tag_id' => 2, 'value' => 'Malicious File - T1204.002', 'Galaxy' => $enterprise],
            ['tag_id' => 3, 'value' => 'Phishing - T1566', 'Galaxy' => $enterprise],
            $this->cluster(4, 'Legacy - T1566', 'stix-2.1-attack-pattern'),
        ];
        $rows = EventContextTool::rows([], $clusters, null, [], [], $this->profile());
        $groups = EventContextTool::byGalaxy($rows['behaviour']);

        $this->assertSame(
            ['Attack Pattern', 'Mobile Attack - Attack Pattern', 'stix-2.1-attack-pattern'],
            array_column(array_column($groups, 'galaxy'), 'name')
        );
        $this->assertSame(
            ['cluster:event:Malicious File - T1204.002', 'cluster:event:Phishing - T1566'],
            $this->keys($groups[0]['items'])
        );
    }

    public function testIcsTechniquesReadTheirIdFromTheirOwnKey(): void
    {
        $ics = ['value' => 'Masquerading', 'meta' => ['Technique ID' => ['T849'], 'Tactic' => ['Evasion']]];
        $this->assertSame('T849', EventContextTool::techniqueId($ics));
        $this->assertNull(EventContextTool::techniqueId(['value' => 'Masquerading', 'meta' => []]));
    }

    public function testIndicatorOnlyLabelsJoinTheirRowAfterEventOnes(): void
    {
        $tags = [$this->eventTag(3, 'phishing:techniques="fake-website"')];
        $rollup = [3 => 2, 7 => 3, 8 => 16, 9 => 2];
        $rollupTags = [
            7 => ['id' => 7, 'name' => 'phishing:state="active"', 'is_galaxy' => 0, 'hide_tag' => 0],
            8 => ['id' => 8, 'name' => 'misp-galaxy:mitre-attack-pattern="Exfiltration Over C2 Channel - T1646"', 'is_galaxy' => 1, 'hide_tag' => 0],
            9 => ['id' => 9, 'name' => 'misp-galaxy:mitre-course-of-action="Network Intrusion Prevention - M1031"', 'is_galaxy' => 1, 'hide_tag' => 0],
        ];
        $rollupClusters = [
            8 => $this->cluster(8, 'Exfiltration Over C2 Channel - T1646', 'mitre-attack-pattern'),
            9 => $this->cluster(9, 'Network Intrusion Prevention - M1031', 'mitre-course-of-action'),
        ];
        $rows = EventContextTool::rows($tags, [], $rollup, $rollupTags, $rollupClusters, $this->profile());

        $this->assertSame(
            ['tag:event:phishing:techniques="fake-website"', 'tag:indicators:phishing:state="active"'],
            $this->keys($rows['classification'])
        );
        $this->assertSame(2, $rows['classification'][0]['count']);
        $this->assertSame(3, $rows['classification'][1]['count']);
        $this->assertSame(['cluster:indicators:Exfiltration Over C2 Channel - T1646'], $this->keys($rows['behaviour']));
        $this->assertSame(16, $rows['behaviour'][0]['count']);
        $this->assertSame(['cluster:indicators:Network Intrusion Prevention - M1031'], $this->keys($rows['mitigation']));
        $this->assertSame('M1031', $rows['mitigation'][0]['technique']);
    }

    public function testAProfileMarkingLeavesClassificationAndOthersReturn(): void
    {
        $tags = [
            $this->eventTag(1, 'tlp:amber'),
            $this->eventTag(2, 'PAP:AMBER'),
            $this->eventTag(10, 'nato:classification="NATO RESTRICTED"'),
        ];
        $rows = EventContextTool::rows($tags, [], null, [], [], $this->profile(['markings' => ['nato', 'tlp']]));

        $this->assertSame(
            ['tag:event:nato:classification="NATO RESTRICTED"', 'tag:event:tlp:amber'],
            $this->keys($rows['markings'])
        );
        $this->assertSame(['tag:event:PAP:AMBER'], $this->keys($rows['classification']));
    }

    public function testPinnedAbsenceIsDrawnWhereTheDimensionLives(): void
    {
        $profile = $this->profile(['taxonomies' => [
            'pinned' => ['tlp', 'false-positive'], 'preferred' => [], 'demoted' => [],
        ]]);
        $rows = EventContextTool::rows(
            [$this->eventTag(3, 'circl:incident-classification="malware"')],
            [], null, [], [], $profile,
            ['taxonomies' => ['tlp', 'false-positive']]
        );

        $this->assertSame([['key' => 'tlp']], $rows['markings_absent']);
        $this->assertSame('absent', $rows['classification'][0]['kind']);
        $this->assertSame('false-positive', $rows['classification'][0]['key']);
    }

    public function testADisabledPinnedTaxonomyDrawsNoAbsence(): void
    {
        $profile = $this->profile(['taxonomies' => [
            'pinned' => ['false-positive'], 'preferred' => [], 'demoted' => [],
        ]]);
        $rows = EventContextTool::rows([], [], null, [], [], $profile, ['taxonomies' => []]);

        $this->assertSame([], $rows['classification']);
    }

    public function testHiddenTagsStayHidden(): void
    {
        $rows = EventContextTool::rows(
            [$this->eventTag(3, 'workflow:state="draft"', ['hide_tag' => 1])],
            [], null, [], [], $this->profile()
        );
        $this->assertSame([], $rows['classification']);
    }

    public function testGroupsFollowTheType(): void
    {
        $this->assertSame('Network', EventOverviewTool::groupOf('ip-dst'));
        $this->assertSame('Network', EventOverviewTool::groupOf('domain|ip'));
        $this->assertSame('Network', EventOverviewTool::groupOf('url'));
        $this->assertSame('File', EventOverviewTool::groupOf('sha256'));
        $this->assertSame('File', EventOverviewTool::groupOf('malware-sample'));
        $this->assertSame('Email', EventOverviewTool::groupOf('email-subject'));
        $this->assertSame('Host', EventOverviewTool::groupOf('regkey|value'));
        $this->assertSame('Detection rules', EventOverviewTool::groupOf('snort'));
        $this->assertSame('Detection rules', EventOverviewTool::groupOf('pattern-in-file'));
        $this->assertSame('Other', EventOverviewTool::groupOf('text'));
    }

    public function testRuleNamesComeFromTheRule(): void
    {
        $this->assertSame(
            'Block traffic to specific domains',
            EventOverviewTool::ruleName('snort', 'drop ip any any -> any any (msg:"Block traffic to specific domains"; sid:1;)', '')
        );
        $this->assertSame('Loader_Strings', EventOverviewTool::ruleName('yara', "import \"pe\"\nrule Loader_Strings {\n}", ''));
        $this->assertSame('Suspicious PowerShell', EventOverviewTool::ruleName('sigma', "title: Suspicious PowerShell\nstatus: test", ''));
        $this->assertSame('fallback', EventOverviewTool::ruleName('zeek', 'event x() {}', 'fallback'));
    }

    public function testNarrowerScope(): void
    {
        // event shared with connected communities (2)
        $this->assertFalse(EventOverviewTool::isNarrower(2, 0, 2, 0));
        $this->assertFalse(EventOverviewTool::isNarrower(3, 0, 2, 0));
        $this->assertTrue(EventOverviewTool::isNarrower(1, 0, 2, 0));
        $this->assertTrue(EventOverviewTool::isNarrower(0, 0, 2, 0));
        $this->assertTrue(EventOverviewTool::isNarrower(4, 7, 2, 0));
        // event in sharing group 7
        $this->assertFalse(EventOverviewTool::isNarrower(4, 7, 4, 7));
        $this->assertTrue(EventOverviewTool::isNarrower(4, 8, 4, 7));
        $this->assertTrue(EventOverviewTool::isNarrower(0, 0, 4, 7));
        $this->assertFalse(EventOverviewTool::isNarrower(3, 0, 4, 7));
        // an organisation-only event leaves nothing narrower
        $this->assertFalse(EventOverviewTool::isNarrower(4, 7, 0, 0));
        $this->assertFalse(EventOverviewTool::isNarrower(0, 0, 0, 0));
    }

    private function inventoryPart(array $groups, array $objects, array $rules, $narrower = 0)
    {
        $total = $ids = 0;
        foreach ($groups as $group) {
            $total += $group['total'];
            $ids += $group['ids'];
        }
        return [
            'total' => $total, 'ids' => $ids, 'context' => $total - $ids,
            'narrower' => $narrower, 'narrower_in_objects' => 0,
            'groups' => $groups,
            'objects' => ['total' => array_sum($objects), 'by_name' => $objects],
            'detection_rules' => $rules,
        ];
    }

    public function testMergedInventoriesAddUpGroupsTypesAndObjects(): void
    {
        $merged = EventOverviewTool::mergeInventories([
            1 => $this->inventoryPart(
                [['group' => 'Network', 'total' => 3, 'ids' => 2, 'in_objects' => 1, 'types' => [
                    ['type' => 'domain', 'total' => 2, 'ids' => 2], ['type' => 'url', 'total' => 1, 'ids' => 0],
                ]]],
                ['domain-ip' => 2],
                [],
                1
            ),
            7 => $this->inventoryPart(
                [
                    ['group' => 'File', 'total' => 1, 'ids' => 0, 'in_objects' => 0, 'types' => [['type' => 'filename', 'total' => 1, 'ids' => 0]]],
                    ['group' => 'Network', 'total' => 4, 'ids' => 4, 'in_objects' => 0, 'types' => [['type' => 'url', 'total' => 4, 'ids' => 4]]],
                ],
                ['file' => 3, 'domain-ip' => 1],
                [],
                2
            ),
        ]);
        $this->assertSame(8, $merged['total']);
        $this->assertSame(6, $merged['ids']);
        $this->assertSame(2, $merged['context']);
        $this->assertSame(3, $merged['narrower']);
        $this->assertSame(['Network', 'File'], array_column($merged['groups'], 'group'));
        $this->assertSame(7, $merged['groups'][0]['total']);
        $this->assertSame(
            [['type' => 'url', 'total' => 5, 'ids' => 4], ['type' => 'domain', 'total' => 2, 'ids' => 2]],
            $merged['groups'][0]['types']
        );
        $this->assertSame(['domain-ip' => 3, 'file' => 3], $merged['objects']['by_name']);
        $this->assertSame(6, $merged['objects']['total']);
    }

    public function testMergedDetectionRulesKeepTheirEventAndStopAtFive(): void
    {
        $rule = function ($name) {
            return ['type' => 'yara', 'name' => $name, 'object' => null];
        };
        $merged = EventOverviewTool::mergeInventories([
            1 => $this->inventoryPart([], [], [$rule('a'), $rule('b'), $rule('c')]),
            8 => $this->inventoryPart([], [], [$rule('d'), $rule('e'), $rule('f')]),
        ]);
        $this->assertSame(['a', 'b', 'c', 'd', 'e'], array_column($merged['detection_rules'], 'name'));
        $this->assertSame([1, 1, 1, 8, 8], array_column($merged['detection_rules'], 'event_id'));
    }

    public function testActivityHistogramRunsFromFirstChangeToToday(): void
    {
        $this->assertNull(EventOverviewTool::activityHistogram(['first' => null, 'days' => []], '2026-10-05'));

        $histogram = EventOverviewTool::activityHistogram([
            'first' => strtotime('2026-09-20 10:00:00'),
            'days' => ['2026-09-20' => 3, '2026-09-22' => 1],
        ], '2026-10-05');
        $this->assertSame('day', $histogram['unit']);
        $this->assertSame(3, $histogram['max']);
        $this->assertCount(16, $histogram['bars']);
        $this->assertSame('2026-09-20', $histogram['bars'][0]['from']);
        $this->assertSame('2026-10-05', end($histogram['bars'])['to']);
        $this->assertSame([3, 0, 1], array_slice(array_column($histogram['bars'], 'count'), 0, 3));
    }

    public function testActivityAxisMarksMonthsButNotTheOpeningBar(): void
    {
        $histogram = EventOverviewTool::activityHistogram([
            'first' => strtotime('2026-09-20 10:00:00'),
            'days' => ['2026-09-20' => 1],
        ], '2026-10-05');
        $scale = ValueStatsTool::timeScale($histogram);
        $this->assertArrayNotHasKey(0, $scale);
        $this->assertSame(['Oct'], array_values(array_filter($scale)));
    }
}
