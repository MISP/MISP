<?php

require_once __DIR__ . '/IntegrationTestCase.php';

/**
 * Specification tests for the three pure transforms in Server's pull path:
 *
 *   - filterRuleToParameter()          - sync filter rules to search parameters
 *   - __checkIfEventSaveAble()         - "is there anything left worth saving"
 *   - __updatePulledEventBeforeInsert() - the distribution downgrade cascade
 *
 * None of them touches the network or the database: they are array in, array
 * out. They were nevertheless completely uncovered, because they sit inside
 * pull(), which does need a remote instance. Driving them directly is the
 * cheapest coverage in the whole sync path, and the downgrade cascade in
 * particular is security-relevant - it is what stops a pulled event being
 * redistributed more widely than its origin intended.
 *
 * Unlike the Event characterization tests these are SPECIFICATIONS (ADR 0002):
 * the distribution downgrade is a documented rule, not an accident, so a change
 * that breaks one of these assertions is a bug rather than a re-baseline.
 *
 * The last two are private, so they are reached by reflection. That is
 * deliberate: making them public purely to test them would widen Server's API
 * for no caller's benefit.
 */
class ServerPullTransformTest extends IntegrationTestCase
{
    /** @var array<string,mixed> config keys this test writes, with their prior values */
    private $savedConfig = [];

    protected function tearDown(): void
    {
        foreach ($this->savedConfig as $key => $value) {
            if ($value === null) {
                Configure::delete($key);
            } else {
                Configure::write($key, $value);
            }
        }
        $this->savedConfig = [];
        parent::tearDown();
    }

    private function setConfig(string $key, $value): void
    {
        if (!array_key_exists($key, $this->savedConfig)) {
            $this->savedConfig[$key] = Configure::check($key) ? Configure::read($key) : null;
        }
        Configure::write($key, $value);
    }

    private function server()
    {
        return $this->model('Server');
    }

    private function callPrivate(string $method, array &$args)
    {
        $reflection = new ReflectionMethod('Server', $method);
        $reflection->setAccessible(true);
        return $reflection->invokeArgs($this->server(), $args);
    }

    // ------------------------------------------------ filterRuleToParameter

    public function testEmptyFilterRulesProduceNoParameters(): void
    {
        $this->assertSame([], $this->server()->filterRuleToParameter(''));
        $this->assertSame([], $this->server()->filterRuleToParameter('[]'));
    }

    public function testPluralRuleFieldsAreSingularisedForTheSearchApi(): void
    {
        // 'tags' => 'tag', 'orgs' => 'org' - the search API takes the singular.
        $rules = json_encode(['tags' => ['OR' => ['tlp:white']], 'orgs' => ['OR' => ['CIRCL']]]);
        $out = $this->server()->filterRuleToParameter($rules);
        $this->assertSame(['tag' => ['tlp:white'], 'org' => ['CIRCL']], $out);
    }

    public function testNotRulesBecomeBangPrefixedValues(): void
    {
        $rules = json_encode(['tags' => ['NOT' => ['tlp:red', 'tlp:amber']]]);
        $this->assertSame(['tag' => ['!tlp:red', '!tlp:amber']], $this->server()->filterRuleToParameter($rules));
    }

    public function testOrAndNotRulesForOneFieldAreFlattenedTogether(): void
    {
        $rules = json_encode(['tags' => ['OR' => ['tlp:white'], 'NOT' => ['tlp:red']]]);
        $this->assertSame(['tag' => ['tlp:white', '!tlp:red']], $this->server()->filterRuleToParameter($rules));
    }

    public function testEmptyRuleValuesAreDropped(): void
    {
        $rules = json_encode(['tags' => ['OR' => ['', 'tlp:white', '']]]);
        $this->assertSame(['tag' => ['tlp:white']], $this->server()->filterRuleToParameter($rules));
    }

    public function testAFieldWhoseValuesAreAllEmptyProducesNoParameter(): void
    {
        $rules = json_encode(['tags' => ['OR' => ['', '']]]);
        $this->assertSame([], $this->server()->filterRuleToParameter($rules));
    }

    public function testUrlParamsAreMergedRatherThanSingularised(): void
    {
        $rules = json_encode([
            'tags' => ['OR' => ['tlp:white']],
            'url_params' => json_encode(['published' => 1]),
        ]);
        $out = $this->server()->filterRuleToParameter($rules);
        $this->assertSame(['tlp:white'], $out['tag']);
        $this->assertSame(1, $out['published'], 'url_params are merged in verbatim, keeping their own key');
        $this->assertArrayNotHasKey('url_param', $out, 'url_params is not a plural field to singularise');
    }

    public function testEmptyUrlParamsAreIgnored(): void
    {
        $rules = json_encode(['tags' => ['OR' => ['tlp:white']], 'url_params' => '']);
        $this->assertSame(['tag' => ['tlp:white']], $this->server()->filterRuleToParameter($rules));
    }

    // ------------------------------------------------- __checkIfEventSaveAble

    private function saveable(array $event): bool
    {
        $args = [$event];
        return $this->callPrivate('__checkIfEventSaveAble', $args);
    }

    public function testAnEmptyEventIsNotWorthSaving(): void
    {
        $this->assertFalse($this->saveable(['Event' => []]));
    }

    public function testOneLiveAttributeMakesAnEventSaveable(): void
    {
        $this->assertTrue($this->saveable(['Event' => ['Attribute' => [['deleted' => false]]]]));
    }

    public function testAnEventOfOnlyDeletedAttributesIsNotSaveable(): void
    {
        $this->assertFalse($this->saveable(['Event' => ['Attribute' => [['deleted' => true]]]]));
    }

    public function testALiveAttributeInsideALiveObjectMakesAnEventSaveable(): void
    {
        $this->assertTrue($this->saveable(['Event' => ['Object' => [
            ['deleted' => false, 'Attribute' => [['deleted' => false]]],
        ]]]));
    }

    public function testALiveAttributeInsideADeletedObjectDoesNotCount(): void
    {
        $this->assertFalse($this->saveable(['Event' => ['Object' => [
            ['deleted' => true, 'Attribute' => [['deleted' => false]]],
        ]]]));
    }

    public function testAnObjectWithNoAttributesDoesNotMakeAnEventSaveable(): void
    {
        $this->assertFalse($this->saveable(['Event' => ['Object' => [['deleted' => false]]]]));
    }

    public function testALiveEventReportAloneMakesAnEventSaveable(): void
    {
        $this->assertTrue($this->saveable(['Event' => ['EventReport' => [['deleted' => false]]]]));
    }

    public function testADeletedEventReportAloneDoesNot(): void
    {
        $this->assertFalse($this->saveable(['Event' => ['EventReport' => [['deleted' => true]]]]));
    }

    // --------------------------------------- __updatePulledEventBeforeInsert

    private function pullUser(): array
    {
        return ['id' => 42, 'email' => 'puller@example.com'];
    }

    private function externalServer(): array
    {
        return ['Server' => ['id' => 1, 'internal' => 0, 'org_id' => 1]];
    }

    /**
     * @return array{0:array,1:bool} the transformed event and the
     *         "pull rules emptied this event" flag
     */
    private function transform(array $event, array $server = null, array $pullRules = [], $remoteUser = false): array
    {
        $server = $server ?: $this->externalServer();
        $args = [&$event, $server, $this->pullUser(), $pullRules, $remoteUser];
        $emptied = $this->callPrivate('__updatePulledEventBeforeInsert', $args);
        return [$event, $emptied];
    }

    public function testAPulledEventIsAlwaysLockedAndReattributed(): void
    {
        [$event] = $this->transform(['Event' => ['distribution' => '0']]);
        $this->assertTrue($event['Event']['locked'], 'a pulled event must be locked against local edits');
        $this->assertSame(42, $event['Event']['user_id'], 'the pulling admin becomes the reporter');
    }

    public function testAVersionOneEventWithoutDistributionDefaultsToCommunity(): void
    {
        // No distribution key at all - MISP 1.x events. It is defaulted to '1'
        // and then immediately downgraded to '0' by the external-server rule.
        [$event] = $this->transform(['Event' => []]);
        $this->assertSame('0', $event['Event']['distribution']);
    }

    public function testCommunityOnlyIsDowngradedToOrganisationOnly(): void
    {
        [$event] = $this->transform(['Event' => ['distribution' => 1]]);
        $this->assertSame('0', $event['Event']['distribution']);
    }

    public function testConnectedCommunitiesIsDowngradedToCommunityOnly(): void
    {
        [$event] = $this->transform(['Event' => ['distribution' => 2]]);
        $this->assertSame('1', $event['Event']['distribution']);
    }

    public function testAllCommunitiesAndSharingGroupAreLeftAlone(): void
    {
        [$allCommunities] = $this->transform(['Event' => ['distribution' => 3]]);
        $this->assertSame(3, $allCommunities['Event']['distribution']);
        [$sharingGroup] = $this->transform(['Event' => ['distribution' => 4]]);
        $this->assertSame(4, $sharingGroup['Event']['distribution']);
    }

    public function testTheDowngradeCascadesToAttributesObjectsAndReports(): void
    {
        [$event] = $this->transform(['Event' => [
            'distribution' => '2',
            'Attribute' => [['type' => 'ip-dst', 'distribution' => '1'], ['type' => 'domain', 'distribution' => '2']],
            'Object' => [[
                'template_uuid' => 'tpl-1',
                'distribution' => '2',
                'Attribute' => [['type' => 'md5', 'distribution' => '1']],
            ]],
            'EventReport' => [['distribution' => '1'], ['distribution' => '2']],
        ]]);

        $this->assertSame('0', $event['Event']['Attribute'][0]['distribution']);
        $this->assertSame('1', $event['Event']['Attribute'][1]['distribution']);
        $this->assertSame('1', $event['Event']['Object'][0]['distribution']);
        $this->assertSame('0', $event['Event']['Object'][0]['Attribute'][0]['distribution']);
        $this->assertSame('0', $event['Event']['EventReport'][0]['distribution']);
        $this->assertSame('1', $event['Event']['EventReport'][1]['distribution']);
    }

    public function testAnInternalServerInTheHostOrgSkipsEveryDowngrade(): void
    {
        // All four conditions must hold: host_org_id set, the server flagged
        // internal, the server owned by the host org, and the remote user
        // holding perm_sync_internal. This is the internal-sync exemption.
        $this->setConfig('MISP.host_org_id', 7);
        [$event] = $this->transform(
            ['Event' => ['distribution' => '1', 'Attribute' => [['type' => 'ip-dst', 'distribution' => '1']]]],
            ['Server' => ['id' => 1, 'internal' => 1, 'org_id' => 7]],
            [],
            ['Role' => ['perm_sync_internal' => 1]]
        );
        $this->assertSame('1', $event['Event']['distribution'], 'internal sync preserves distribution');
        $this->assertSame('1', $event['Event']['Attribute'][0]['distribution']);
    }

    public function testAnInternalServerWithoutThePermissionStillDowngrades(): void
    {
        $this->setConfig('MISP.host_org_id', 7);
        [$event] = $this->transform(
            ['Event' => ['distribution' => '1']],
            ['Server' => ['id' => 1, 'internal' => 1, 'org_id' => 7]],
            [],
            ['Role' => ['perm_sync_internal' => 0]]
        );
        $this->assertSame('0', $event['Event']['distribution']);
    }

    public function testAnInternalServerOfAnotherOrgStillDowngrades(): void
    {
        $this->setConfig('MISP.host_org_id', 7);
        [$event] = $this->transform(
            ['Event' => ['distribution' => '1']],
            ['Server' => ['id' => 1, 'internal' => 1, 'org_id' => 8]],
            [],
            ['Role' => ['perm_sync_internal' => 1]]
        );
        $this->assertSame('0', $event['Event']['distribution']);
    }

    // ---- pull rules: type filtering ------------------------------------

    public function testTypeFilteringIsInertUntilTheFeatureIsEnabled(): void
    {
        $this->setConfig('MISP.enable_synchronisation_filtering_on_type', false);
        [$event, $emptied] = $this->transform(
            ['Event' => ['distribution' => '0', 'Attribute' => [['type' => 'ip-dst', 'distribution' => '0']]]],
            null,
            ['type_attributes' => ['NOT' => ['ip-dst']]]
        );
        $this->assertCount(1, $event['Event']['Attribute'], 'the setting gates the whole filter');
        $this->assertFalse($emptied);
    }

    public function testBlockedAttributeTypesAreStrippedWhenEnabled(): void
    {
        $this->setConfig('MISP.enable_synchronisation_filtering_on_type', true);
        [$event, $emptied] = $this->transform(
            ['Event' => ['distribution' => '0', 'Attribute' => [
                ['type' => 'ip-dst', 'distribution' => '0'],
                ['type' => 'domain', 'distribution' => '0'],
            ]]],
            null,
            ['type_attributes' => ['NOT' => ['ip-dst']]]
        );
        $this->assertCount(1, $event['Event']['Attribute']);
        $this->assertFalse($emptied, 'something survived, so the event was not emptied');
    }

    public function testAnEventStrippedOfEveryAttributeIsReportedAsEmptied(): void
    {
        $this->setConfig('MISP.enable_synchronisation_filtering_on_type', true);
        [$event, $emptied] = $this->transform(
            ['Event' => ['distribution' => '0', 'Attribute' => [['type' => 'ip-dst', 'distribution' => '0']]]],
            null,
            ['type_attributes' => ['NOT' => ['ip-dst']]]
        );
        $this->assertEmpty($event['Event']['Attribute']);
        $this->assertTrue($emptied, 'the caller needs to know the pull rules, not the remote, emptied this');
    }

    public function testAnEventThatArrivedWithNoAttributesIsNotReportedAsEmptied(): void
    {
        // originalCount is 0, so the pull rules cannot be blamed.
        $this->setConfig('MISP.enable_synchronisation_filtering_on_type', true);
        [, $emptied] = $this->transform(
            ['Event' => ['distribution' => '0', 'Attribute' => []]],
            null,
            ['type_attributes' => ['NOT' => ['ip-dst']]]
        );
        $this->assertFalse($emptied);
    }

    public function testBlockedObjectTemplatesAreStripped(): void
    {
        $this->setConfig('MISP.enable_synchronisation_filtering_on_type', true);
        [$event, $emptied] = $this->transform(
            ['Event' => ['distribution' => '0', 'Object' => [
                ['template_uuid' => 'blocked-tpl', 'distribution' => '0', 'Attribute' => []],
            ]]],
            null,
            ['type_objects' => ['NOT' => ['blocked-tpl']]]
        );
        $this->assertEmpty($event['Event']['Object']);
        $this->assertTrue($emptied);
    }

    public function testAnObjectLeftWithNoAttributesIsDiscardedEntirely(): void
    {
        $this->setConfig('MISP.enable_synchronisation_filtering_on_type', true);
        [$event] = $this->transform(
            ['Event' => ['distribution' => '0', 'Object' => [
                ['template_uuid' => 'tpl-1', 'distribution' => '0', 'Attribute' => [
                    ['type' => 'ip-dst', 'distribution' => '0'],
                ]],
            ]]],
            null,
            ['type_attributes' => ['NOT' => ['ip-dst']]]
        );
        $this->assertEmpty($event['Event']['Object'], 'an object with every attribute filtered out is dropped');
    }
}
