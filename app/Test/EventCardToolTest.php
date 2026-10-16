<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}
if (!function_exists('__n')) {
    function __n($singular, $plural, $count, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($count == 1 ? $singular : $plural, array_slice($arguments, 3));
    }
}
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueLabelPriority.php';
require_once __DIR__ . '/../Lib/Tools/GalaxyCategory.php';
require_once __DIR__ . '/../Lib/Tools/EventOverview/EventContextTool.php';
require_once __DIR__ . '/../Lib/Tools/DistributionLevel.php';
require_once __DIR__ . '/../Lib/Tools/EventOverview/EventCardTool.php';

use PHPUnit\Framework\TestCase;

class EventCardToolTest extends TestCase
{
    protected function setUp(): void
    {
        GalaxyCategory::prime([
            'threat-actor' => ['named-threat', 'actor'],
            'malpedia' => ['named-threat', 'malware'],
            'stealer' => ['named-threat', 'malware'],
            'mitre-attack-pattern' => ['technique', 'attack-pattern'],
            'mitre-course-of-action' => ['defensive', 'course-of-action'],
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

    private function galaxyTag($id, $type, $value)
    {
        return $this->eventTag($id, sprintf('misp-galaxy:%s="%s"', $type, $value), ['is_galaxy' => 1]);
    }

    private function cluster($tagId, $value, $type, array $meta = [])
    {
        return [
            'tag_id' => $tagId,
            'value' => $value,
            'meta' => $meta,
            'Galaxy' => ['type' => $type, 'name' => $type, 'icon' => 'globe'],
        ];
    }

    private function rows(array $eventTags, array $clusters)
    {
        $context = EventContextTool::rows($eventTags, $clusters, null, [], [], null, ['taxonomies' => ['tlp', 'pap']]);
        return EventCardTool::rows($context);
    }

    private function labels(array $chips)
    {
        return array_map(function ($chip) {
            return $chip['kind'] . ':' . ($chip['label'] ?? $chip['count']);
        }, $chips);
    }

    public function testThreeRows(): void
    {
        $rows = $this->rows(
            [$this->eventTag(1, 'tlp:amber'), $this->eventTag(2, 'type:OSINT')],
            [
                $this->cluster(10, 'APT28', 'threat-actor'),
                $this->cluster(11, 'Phishing - T1566', 'mitre-attack-pattern', ['external_id' => ['T1566']]),
                $this->cluster(12, 'User Training - M1017', 'mitre-course-of-action', ['external_id' => ['M1017']]),
                $this->cluster(13, 'Finance', 'sector'),
            ]
        );
        $this->assertSame(['cluster:APT28'], $this->labels($rows['attribution']));
        $this->assertTrue($rows['attribution'][0]['attribution']);
        $this->assertSame(['technique:T1566', 'mitigation:M1017'], $this->labels($rows['behaviour']));
        $this->assertSame('Phishing', $rows['behaviour'][0]['name']);
        $this->assertSame(['cluster:Finance', 'tag:OSINT'], $this->labels($rows['classification']));
        $this->assertSame('type', $rows['classification'][1]['namespace']);
        $this->assertSame(1, $rows['attribution_count']);
        $this->assertSame(1, $rows['technique_count']);
    }

    public function testUnresolvedGalaxyTagsAreRouted(): void
    {
        $rows = $this->rows(
            [
                $this->galaxyTag(1, 'mitre-attack-pattern', 'Connection Proxy - T1090'),
                $this->galaxyTag(2, 'stix-2.1-attack-pattern', '7e6945c5-7f3b-55f6-bcb7-fa324c6bdaed'),
                $this->galaxyTag(3, 'stix-2.1-attack-pattern', 'cfbd0546-fbbe-50bc-9839-f5942a2351aa'),
                $this->galaxyTag(4, 'sector', 'Shipping'),
                $this->eventTag(5, 'misp:tool="misp2yara"'),
            ],
            [$this->cluster(10, 'Proxy - T1090', 'mitre-attack-pattern', ['external_id' => 'T1090'])]
        );
        $this->assertSame(['technique:T1090'], $this->labels($rows['behaviour']), 'the unheld T1090 joins the held one');
        $this->assertSame(1, $rows['technique_count']);
        $this->assertSame(['unheld:Shipping', 'tag:misp2yara', 'fold:2'], $this->labels($rows['classification']));
        $this->assertSame('sector', $rows['classification'][0]['galaxy']);
        $this->assertSame('tool', $rows['classification'][1]['namespace']);
        foreach ($rows['classification'] as $chip) {
            $this->assertStringNotContainsString('misp-galaxy:', $chip['label'] ?? '');
        }
    }

    public function testUnheldAttributionTagsJoinTheAttributionRow(): void
    {
        $held = $this->cluster(3, 'Sandworm', 'threat-actor');
        $held['Galaxy'] = ['id' => 7, 'name' => 'Threat Actor', 'icon' => 'user-secret'] + $held['Galaxy'];
        $tags = [
            $this->galaxyTag(1, 'threat-actor', 'ELECTRUM'),
            $this->galaxyTag(2, 'Threat-Actor', 'TeleBots'),
            $this->galaxyTag(3, 'threat-actor', 'Sandworm'),
            $this->galaxyTag(4, 'threat-actor', 'a5a2b1f3-0000-4000-8000-000000000000'),
            $this->galaxyTag(5, 'sector', 'Energy'),
        ];
        $context = EventContextTool::rows($tags, [$held], null, [], [], null, ['taxonomies' => []]);
        $this->assertSame(['cluster', 'unheld', 'unheld'], array_column($context['attribution'], 'kind'));
        $this->assertSame('Threat Actor', $context['attribution'][1]['galaxy']['name']);

        $rows = EventCardTool::rows($context);
        $this->assertSame(
            ['cluster:Sandworm', 'unheld:ELECTRUM', 'unheld:TeleBots'],
            $this->labels($rows['attribution']),
            'held clusters first'
        );
        $this->assertTrue($rows['attribution'][1]['attribution']);
        $this->assertSame('Threat Actor', $rows['attribution'][1]['galaxy']);
        $this->assertSame('Threat Actor', $rows['attribution'][1]['source']['unheld']['galaxy']);
        $this->assertSame(3, $rows['attribution_count']);
        $this->assertSame(['unheld:Energy', 'fold:1'], $this->labels($rows['classification']));

        $narrow = ['galaxies' => ['attribution' => ['mitre-intrusion-set']]];
        $context = EventContextTool::rows($tags, [], null, [], [], $narrow, ['taxonomies' => []]);
        $this->assertSame([], $context['attribution'], 'the profile decides which galaxies count');
    }

    public function testChipsCarryTheRowsTheirPopoverLists(): void
    {
        $held = $this->cluster(10, 'Valid Accounts - T1078', 'mitre-attack-pattern', ['external_id' => 'T1078']);
        $held['Galaxy'] = ['id' => 7, 'name' => 'MITRE ATT&CK Techniques', 'icon' => 'map'] + $held['Galaxy'];
        $rows = $this->rows(
            [
                $this->galaxyTag(1, 'mitre-attack-pattern', 'Connection Proxy - T1090'),
                $this->galaxyTag(2, 'sector', 'Shipping'),
                $this->eventTag(3, 'type:OSINT'),
            ],
            [$held]
        );
        $this->assertSame('Valid Accounts - T1078', $rows['behaviour'][0]['source']['cluster']['value']);
        $this->assertSame([
            'value' => 'Connection Proxy - T1090',
            'galaxy' => 'MITRE ATT&CK Techniques',
            'galaxy_id' => 7,
            'icon' => 'map',
        ], $rows['behaviour'][1]['source']['unheld'], 'listed in the held galaxy');
        $this->assertSame('sector', $rows['classification'][0]['source']['unheld']['galaxy'], 'no held galaxy of that type');
        $this->assertSame('type:OSINT', $rows['classification'][1]['source']['tag']['Tag']['name']);
    }

    public function testUnheldTechniqueIsDashed(): void
    {
        $rows = $this->rows([$this->galaxyTag(1, 'mitre-attack-pattern', 'Connection Proxy - T1090')], []);
        $this->assertSame(['technique:T1090'], $this->labels($rows['behaviour']));
        $this->assertTrue($rows['behaviour'][0]['unheld']);
        $this->assertSame('Connection Proxy', $rows['behaviour'][0]['name']);
        $this->assertSame([], $rows['classification']);
    }

    public function testClusterHeldByTwoGalaxiesShowsOnce(): void
    {
        $rows = $this->rows([], [
            $this->cluster(10, 'Vidar', 'malpedia'),
            $this->cluster(11, 'Vidar', 'stealer'),
            $this->cluster(12, 'Exploitation - T1203', 'mitre-enterprise-attack-course-of-action', ['external_id' => 'T1203']),
            $this->cluster(13, 'Exploitation - T1203', 'mitre-course-of-action', ['external_id' => 'T1203']),
            $this->cluster(14, 'Kali365', 'tool-sector'),
            $this->cluster(15, 'Kali365', 'tool-sector'),
        ]);
        $this->assertSame(['cluster:Vidar'], $this->labels($rows['attribution']));
        $this->assertSame(['mitigation:T1203'], $this->labels($rows['behaviour']));
        $this->assertSame(['cluster:Kali365'], $this->labels($rows['classification']));
        $this->assertSame(0, $rows['technique_count'], 'mitigations are not techniques');
    }

    public function testClassificationFollowsTheProfileAcrossTagsAndClusters(): void
    {
        $profile = ['context' => [
            'taxonomies' => ['pinned' => ['tlp', 'admiralty-scale'], 'preferred' => ['type']],
            'galaxies' => ['preferred' => ['sector']],
        ]];
        $tags = [
            $this->eventTag(1, 'type:OSINT'),
            $this->eventTag(2, 'admiralty-scale:source-reliability="b"'),
            $this->galaxyTag(3, 'stix-2.1-attack-pattern', '7e6945c5-7f3b-55f6-bcb7-fa324c6bdaed'),
        ];
        $clusters = [
            $this->cluster(20, 'Kali365', 'tool-sector'),
            $this->cluster(21, 'Academia - University', 'sector'),
        ];
        $context = EventContextTool::rows($tags, $clusters, null, [], [], $profile, ['taxonomies' => ['tlp', 'admiralty-scale']]);
        $rows = EventCardTool::rows($context, $profile);
        $this->assertSame(
            ['cluster:Academia - University', 'tag:OSINT', 'cluster:Kali365', 'fold:1'],
            $this->labels($rows['classification'])
        );
        $this->assertSame('preferred', $rows['classification'][0]['priority']);
        $this->assertSame('preferred', $rows['classification'][1]['priority']);
        $this->assertNull($rows['classification'][2]['priority']);

        $plain = $this->labels($this->rows($tags, $clusters)['classification']);
        $this->assertSame(
            ['cluster:Kali365', 'cluster:Academia - University', 'tag:OSINT', 'tag:b', 'fold:1'],
            $plain,
            'without a profile, the order is unchanged'
        );
    }

    public function testEmptyContext(): void
    {
        $rows = $this->rows([], []);
        $this->assertSame([], $rows['attribution']);
        $this->assertSame([], $rows['behaviour']);
        $this->assertSame([], $rows['classification']);
    }

    public function testMarkingsFollowTheProfile(): void
    {
        $context = EventContextTool::rows(
            [$this->eventTag(1, 'tlp:amber', ['colour' => '#FFC000'])],
            [],
            null,
            [],
            [],
            ['parameters' => ['context' => ['taxonomies' => [
                'pinned' => ['tlp', 'pap'], 'preferred' => [], 'demoted' => [],
            ]]]],
            ['taxonomies' => ['tlp', 'pap']]
        );
        $markings = EventCardTool::markings($context, ['tlp', 'pap']);
        $this->assertSame('tlp', $markings['slots'][0]['key']);
        $this->assertSame('amber', $markings['slots'][0]['value']);
        $this->assertFalse($markings['slots'][0]['neutral']);
        $this->assertSame(['key' => 'pap', 'present' => false], $markings['slots'][1]);

        $clear = EventCardTool::markings(['markings' => [
            ['key' => 'tlp', 'name' => 'tlp:clear', 'tag' => ['Tag' => ['colour' => '#ffffff']]],
        ], 'markings_absent' => []], ['tlp', 'pap']);
        $this->assertTrue($clear['slots'][0]['neutral']);
        $this->assertCount(1, $clear['slots'], 'a namespace neither present nor absent gets no slot');

        $none = EventCardTool::markings(['markings' => [], 'markings_absent' => [['key' => 'tlp']]], ['tlp', 'pap']);
        $this->assertSame([['key' => 'tlp', 'present' => false]], $none['slots']);
    }

    private function profileContext(array $tags, array $profile)
    {
        $permitted = ['taxonomies' => ['tlp', 'pap', 'admiralty-scale', 'estimative-language']];
        return EventContextTool::rows($tags, [], null, [], [], $profile, $permitted);
    }

    private function irProfile(array $pinned = ['tlp', 'pap', 'admiralty-scale'])
    {
        return ['context' => ['markings' => ['tlp', 'pap'], 'taxonomies' => ['pinned' => $pinned]]];
    }

    private function slot(array $markings, $key)
    {
        foreach ($markings['slots'] as $slot) {
            if ($slot['key'] === $key) {
                return $slot;
            }
        }
        $this->fail("no $key slot");
    }

    public function testPinnedSlotsFollowTheProfileOrder(): void
    {
        $profile = $this->irProfile(['tlp', 'estimative-language', 'admiralty-scale', 'pap']);
        $context = $this->profileContext([
            $this->eventTag(1, 'tlp:amber', ['colour' => '#FFC000']),
            $this->eventTag(2, 'admiralty-scale:source-reliability="b"'),
            $this->eventTag(3, 'estimative-language:likelihood-probability="likely"', ['colour' => '#123456']),
        ], $profile);
        $markings = EventCardTool::markings($context, ['tlp', 'pap'], EventCardTool::pinned($profile));
        $this->assertSame(
            ['tlp', 'estimative-language', 'admiralty-scale', 'pap'],
            array_column($markings['slots'], 'key')
        );
        $this->assertSame('pinned', $markings['slots'][1]['kind']);
        $this->assertSame('likely', $markings['slots'][1]['tags'][0]['value']);
        $this->assertSame('#123456', $markings['slots'][1]['tags'][0]['colour']);
        $this->assertSame(['key' => 'pap', 'present' => false], $markings['slots'][3]);
    }

    public function testAdmiraltyIsOneCode(): void
    {
        $profile = $this->irProfile();
        $pinned = EventCardTool::pinned($profile);
        $full = $this->profileContext([
            $this->eventTag(1, 'admiralty-scale:information-credibility="2"'),
            $this->eventTag(2, 'admiralty-scale:source-reliability="b"'),
        ], $profile);
        $descriptions = [
            'admiralty-scale:source-reliability="b"' => ['predicate' => 'Source Reliability', 'entry' => 'Usually reliable'],
            'admiralty-scale:information-credibility="2"' => ['predicate' => 'Information Credibility', 'entry' => 'Probably true'],
        ];
        $slot = $this->slot(EventCardTool::markings($full, ['tlp', 'pap'], $pinned, $descriptions), 'admiralty-scale');
        $this->assertSame('admiralty', $slot['kind']);
        $this->assertSame('B2', $slot['code']);
        $this->assertSame('Source Reliability B — Usually reliable · Information Credibility 2 — Probably true', $slot['title']);

        $source = $this->profileContext([$this->eventTag(2, 'admiralty-scale:source-reliability="b"')], $profile);
        $this->assertSame('B·', $this->slot(EventCardTool::markings($source, ['tlp', 'pap'], $pinned), 'admiralty-scale')['code']);
        $credibility = $this->profileContext([$this->eventTag(1, 'admiralty-scale:information-credibility="2"')], $profile);
        $slot = $this->slot(EventCardTool::markings($credibility, ['tlp', 'pap'], $pinned), 'admiralty-scale');
        $this->assertSame('·2', $slot['code']);
        $this->assertSame('information-credibility 2', $slot['title'], 'without a description, the predicate as written');
    }

    public function testAbsentPinnedTaxonomyHasNoSlot(): void
    {
        $profile = $this->irProfile();
        $context = $this->profileContext([$this->eventTag(1, 'tlp:clear', ['colour' => '#ffffff'])], $profile);
        $markings = EventCardTool::markings($context, ['tlp', 'pap'], EventCardTool::pinned($profile));
        $this->assertSame(['tlp', 'pap'], array_column($markings['slots'], 'key'));
        $this->assertFalse($markings['slots'][1]['present']);
    }

    public function testPinnedTagsLeaveTheClassificationRow(): void
    {
        $profile = $this->irProfile();
        $context = $this->profileContext([
            $this->eventTag(1, 'admiralty-scale:source-reliability="b"'),
            $this->eventTag(2, 'type:OSINT'),
        ], $profile);
        $rows = EventCardTool::rows($context, $profile);
        $this->assertSame(['tag:OSINT'], $this->labels($rows['classification']));
        $this->assertSame(
            ['tag:b', 'tag:OSINT'],
            $this->labels(EventCardTool::rows($context)['classification']),
            'without a profile nothing is pinned'
        );
    }

    public function testNoPinnedExtrasKeepsTodaysMarkings(): void
    {
        $profile = $this->irProfile(['tlp', 'pap']);
        $context = $this->profileContext([
            $this->eventTag(1, 'tlp:amber', ['colour' => '#FFC000']),
            $this->eventTag(2, 'type:OSINT'),
        ], $profile);
        $this->assertSame(
            EventCardTool::markings($context, ['tlp', 'pap']),
            EventCardTool::markings($context, ['tlp', 'pap'], EventCardTool::pinned($profile))
        );
        $this->assertSame([], EventCardTool::pinned(null));
    }

    public function testGrade(): void
    {
        $grades = ['55f6ea5e-2c60-40e5-964f-47a8950d210f' => 'B', '5cf66e53-b5f8-43e7-be9a-49880a3b4631' => 'unrated'];
        $this->assertSame('B', EventCardTool::grade(['uuid' => '55F6EA5E-2c60-40e5-964f-47a8950d210f'], $grades));
        $this->assertNull(EventCardTool::grade(['uuid' => '5cf66e53-b5f8-43e7-be9a-49880a3b4631'], $grades), 'unrated draws nothing');
        $this->assertNull(EventCardTool::grade(['uuid' => '00000000-0000-0000-0000-000000000000'], $grades));
        $this->assertNull(EventCardTool::grade([], $grades));
    }

    public function testTagDescription(): void
    {
        $taxonomy = ['Taxonomy' => ['namespace' => 'admiralty-scale'], 'TaxonomyPredicate' => [[
            'value' => 'source-reliability', 'expanded' => 'Source Reliability',
            'TaxonomyEntry' => [['value' => 'b', 'expanded' => 'Usually reliable']],
        ]]];
        $this->assertSame(['predicate' => 'Source Reliability', 'entry' => 'Usually reliable'], EventCardTool::tagDescription($taxonomy));
        $this->assertSame(['predicate' => null, 'entry' => null], EventCardTool::tagDescription(false));
    }

    public function testState(): void
    {
        $this->assertSame('unpublished', EventCardTool::state(['published' => 0, 'publish_timestamp' => 0, 'timestamp' => 100]));
        $this->assertSame('published', EventCardTool::state(['published' => 1, 'publish_timestamp' => 100, 'timestamp' => 100]));
        $this->assertSame('pending', EventCardTool::state(['published' => 0, 'publish_timestamp' => 100, 'timestamp' => 200]));
        $this->assertSame('pending', EventCardTool::state(['published' => 1, 'publish_timestamp' => 100, 'timestamp' => 200]));
        $this->assertSame('published', EventCardTool::state(['published' => 1, 'publish_timestamp' => 0, 'timestamp' => 200]));
    }

    public function testDistribution(): void
    {
        $all = EventCardTool::distribution(3);
        $this->assertSame('All communities', $all['label']);
        $this->assertSame('fas fa-globe', $all['icon']);
        $this->assertStringContainsString('var(--misp-dist-3-bg, #d1f7e0)', $all['style']);
        $this->assertStringContainsString('var(--misp-dist-3-border, #0f513233)', $all['style']);

        $sg = EventCardTool::distribution('4', ['id' => 2, 'name' => 'CSIRTs'], 12);
        $this->assertSame('Sharing group CSIRTs · 12 organisations', $sg['label']);
        $this->assertStringContainsString('sharing-group', $sg['icon']);

        $this->assertSame('Unknown', EventCardTool::distribution(null)['label']);
    }

    public function testMonogram(): void
    {
        $this->assertSame('CC', EventCardTool::monogram(['name' => 'CIRCL Computer', 'uuid' => 'a'])['letters']);
        $this->assertSame('MI', EventCardTool::monogram(['name' => 'Ministry of the Interior'])['letters']);
        $this->assertSame('AC', EventCardTool::monogram(['name' => 'abuse.ch'])['letters']);
        $this->assertSame('ES', EventCardTool::monogram(['name' => 'ESET'])['letters']);
        $a = EventCardTool::monogram(['name' => 'X', 'uuid' => '5f6e7a1b-0000-0000-0000-000000000000']);
        $this->assertSame($a, EventCardTool::monogram(['name' => 'X', 'uuid' => '5f6e7a1b-0000-0000-0000-000000000000']));
        $this->assertGreaterThanOrEqual(0, $a['index']);
        $this->assertLessThan(6, $a['index']);
    }

    public function testCompactCount(): void
    {
        $this->assertSame('999', EventCardTool::compactCount(999));
        $this->assertSame('1.2k', EventCardTool::compactCount(1234));
        $this->assertSame('2k', EventCardTool::compactCount(2000));
        $this->assertSame('370k', EventCardTool::compactCount(369822));
        $this->assertSame('1.4M', EventCardTool::compactCount(1400000));
    }

    public function testAgo(): void
    {
        $this->assertSame('just now', EventCardTool::ago(1000, 1030));
        $this->assertSame('5 min ago', EventCardTool::ago(0, 300));
        $this->assertSame('3 d ago', EventCardTool::ago(0, 3 * 86400));
        $this->assertSame('2 wk ago', EventCardTool::ago(0, 15 * 86400));
        $this->assertSame('1.5 y ago', EventCardTool::ago(0, (int)(1.5 * 365.25 * 86400)));
    }
}
