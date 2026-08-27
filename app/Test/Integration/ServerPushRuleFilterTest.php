<?php

require_once __DIR__ . '/IntegrationTestCase.php';

/**
 * Specification tests for Server::eventFilterPushableServers() and its private
 * helper convertUUIDsToIDs().
 *
 * These decide which remote instances an event is offered to. Getting them
 * wrong leaks data to a server that was explicitly excluded, so they are
 * specifications rather than characterizations (ADR 0002): a change that
 * breaks one of these assertions is a bug, not a re-baseline.
 *
 * The filter itself is pure - tags and orgs in, servers out - and needs no
 * network. Only the UUID-to-id conversion touches the database, which is why
 * this sits at the integration layer rather than the unit layer.
 */
class ServerPushRuleFilterTest extends IntegrationTestCase
{
    private function server()
    {
        return $this->model('Server');
    }

    /** A server row carrying the given push rules. */
    private function serverWithRules(int $id, array $rules = null): array
    {
        return ['Server' => [
            'id' => $id,
            'name' => "server $id",
            'push_rules' => $rules === null ? '' : json_encode($rules),
        ]];
    }

    /** An event owned by $orgcId carrying $tagIds. */
    private function event(int $orgcId, array $tagIds = []): array
    {
        return [
            'Event' => ['id' => 1, 'orgc_id' => $orgcId],
            'EventTag' => array_map(function ($tagId) {
                return ['tag_id' => $tagId];
            }, $tagIds),
        ];
    }

    /** @return array<int,int> the ids of the servers that survived the filter */
    private function pushable(array $event, array $servers): array
    {
        $result = $this->server()->eventFilterPushableServers($event, $servers);
        return array_map(function ($server) {
            return (int)$server['Server']['id'];
        }, $result);
    }

    // -------------------------------------------------------- no rules at all

    public function testAServerWithoutPushRulesAcceptsEverything(): void
    {
        $this->assertSame(
            [1],
            $this->pushable($this->event(1, [10]), [$this->serverWithRules(1)])
        );
    }

    public function testAllServersAreReturnedWhenNoRuleMatches(): void
    {
        $servers = [$this->serverWithRules(1), $this->serverWithRules(2)];
        $this->assertSame([1, 2], $this->pushable($this->event(1), $servers));
    }

    // ------------------------------------------------------------- tag rules

    public function testAnOrTagRuleRequiresAtLeastOneMatchingTag(): void
    {
        $servers = [$this->serverWithRules(1, ['tags' => ['OR' => [10, 11]]])];
        $this->assertSame([1], $this->pushable($this->event(1, [11]), $servers), 'one shared tag is enough');
        $this->assertSame([], $this->pushable($this->event(1, [99]), $servers), 'no shared tag blocks the push');
    }

    public function testAnOrTagRuleBlocksAnEventWithNoTagsAtAll(): void
    {
        $servers = [$this->serverWithRules(1, ['tags' => ['OR' => [10]]])];
        $this->assertSame([], $this->pushable($this->event(1, []), $servers));
    }

    public function testANotTagRuleBlocksOnAnyMatch(): void
    {
        $servers = [$this->serverWithRules(1, ['tags' => ['NOT' => [10]]])];
        $this->assertSame([], $this->pushable($this->event(1, [10, 11]), $servers), 'one blocked tag is enough');
        $this->assertSame([1], $this->pushable($this->event(1, [11]), $servers));
    }

    public function testNotWinsOverOrWhenBothWouldApply(): void
    {
        // OR is evaluated first and passes, then NOT rejects. The event is
        // blocked: an explicit exclusion beats an inclusion.
        $servers = [$this->serverWithRules(1, ['tags' => ['OR' => [10], 'NOT' => [11]]])];
        $this->assertSame([], $this->pushable($this->event(1, [10, 11]), $servers));
        $this->assertSame([1], $this->pushable($this->event(1, [10]), $servers));
    }

    // ------------------------------------------------------------- org rules

    public function testAnOrOrgRuleRequiresTheEventCreatorToBeListed(): void
    {
        $servers = [$this->serverWithRules(1, ['orgs' => ['OR' => [1]]])];
        $this->assertSame([1], $this->pushable($this->event(1), $servers));
        $this->assertSame([], $this->pushable($this->event(2), $servers));
    }

    public function testANotOrgRuleExcludesTheListedCreator(): void
    {
        $servers = [$this->serverWithRules(1, ['orgs' => ['NOT' => [1]]])];
        $this->assertSame([], $this->pushable($this->event(1), $servers));
        $this->assertSame([1], $this->pushable($this->event(2), $servers));
    }

    public function testOrgRulesAcceptUuidsAsWellAsIds(): void
    {
        // Sync rules are authored against org UUIDs, because ids differ
        // between instances; convertUUIDsToIDs resolves them locally.
        $org = $this->model('Organisation')->find('first', [
            'recursive' => -1,
            'conditions' => ['Organisation.id' => 1],
        ]);
        $this->assertNotEmpty($org, 'this instance needs an organisation with id 1');
        $uuid = $org['Organisation']['uuid'];

        $servers = [$this->serverWithRules(1, ['orgs' => ['OR' => [$uuid]]])];
        $this->assertSame([1], $this->pushable($this->event(1), $servers), 'the uuid must resolve to org 1');
        $this->assertSame([], $this->pushable($this->event(99999), $servers));
    }

    public function testAnUnknownUuidMatchesNothing(): void
    {
        $servers = [$this->serverWithRules(1, [
            'orgs' => ['OR' => ['00000000-0000-4000-8000-000000000000']],
        ])];
        $this->assertSame([], $this->pushable($this->event(1), $servers));
    }

    // ------------------------------------------------------- several servers

    public function testEachServerIsJudgedIndependently(): void
    {
        $servers = [
            $this->serverWithRules(1, ['tags' => ['OR' => [10]]]),
            $this->serverWithRules(2, ['tags' => ['NOT' => [10]]]),
            $this->serverWithRules(3),
        ];
        $this->assertSame(
            [1, 3],
            $this->pushable($this->event(1, [10]), $servers),
            'server 1 requires the tag, server 2 forbids it, server 3 has no opinion'
        );
    }

    public function testTheReturnedListIsNotReindexed(): void
    {
        // $validServers[] = $server, so the survivors are densely keyed even
        // when a server in the middle is dropped.
        $servers = [
            $this->serverWithRules(1, ['tags' => ['NOT' => [10]]]),
            $this->serverWithRules(2),
        ];
        $result = $this->server()->eventFilterPushableServers($this->event(1, [10]), $servers);
        $this->assertSame([0], array_keys($result));
    }

    // -------------------------------------------------------- convertUUIDsToIDs

    private function convert(array $orgs): array
    {
        $reflection = new ReflectionMethod('Server', 'convertUUIDsToIDs');
        $reflection->setAccessible(true);
        return $reflection->invoke($this->server(), $orgs);
    }

    public function testPlainIdsArePassedThroughUnchanged(): void
    {
        $this->assertSame([1, 2], $this->convert([1, 2]));
    }

    public function testAnEmptyRuleConvertsToAnEmptyList(): void
    {
        $this->assertSame([], $this->convert([]));
    }

    public function testAKnownUuidIsResolvedToItsLocalId(): void
    {
        $org = $this->model('Organisation')->find('first', [
            'recursive' => -1,
            'conditions' => ['Organisation.id' => 1],
        ]);
        $this->assertNotEmpty($org, 'this instance needs an organisation with id 1');
        $converted = $this->convert([$org['Organisation']['uuid']]);
        $this->assertSame([1], array_map('intval', $converted));
    }

    public function testIdsAndUuidsCanBeMixedInOneRule(): void
    {
        $org = $this->model('Organisation')->find('first', [
            'recursive' => -1,
            'conditions' => ['Organisation.id' => 1],
        ]);
        $this->assertNotEmpty($org);
        // Ids keep their position at the front; resolved uuids are appended.
        $converted = array_map('intval', $this->convert([42, $org['Organisation']['uuid']]));
        $this->assertSame([42, 1], $converted);
    }
}
