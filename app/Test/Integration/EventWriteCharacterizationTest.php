<?php

require_once __DIR__ . '/IntegrationTestCase.php';
require_once __DIR__ . '/../Support/Snapshot.php';

use MispTest\Support\Snapshot;

/**
 * Characterization of Event's write paths: _add, _edit, quickDelete and
 * processFreeTextData.
 *
 * Together these are ~840 statements and they are where sync, feed ingest and
 * the REST API all write. Nothing pinned them, which makes them the riskiest
 * part of splitting Model/Event.php: a refactor that changes what _edit
 * returns for a stale event, or which errors _add reports, breaks
 * synchronisation in a way no unit test would notice.
 *
 * CHARACTERIZATION, not specification (ADR 0002): these record today's
 * behaviour so a change is detected. Some recorded behaviour is arguably
 * wrong - the stale-update path in particular reports a no-op as an error -
 * and that is captured as-is rather than corrected here.
 */
class EventWriteCharacterizationTest extends IntegrationTestCase
{
    private function payload(string $uuid, string $info, int $timestamp): array
    {
        return ['Event' => [
            'uuid' => $uuid,
            'info' => $info,
            'date' => '2026-01-01',
            'threat_level_id' => 1,
            'analysis' => 0,
            'distribution' => 0,
            'timestamp' => $timestamp,
            'published' => false,
            'Attribute' => [[
                'uuid' => $uuid . '-a1',
                'type' => 'ip-dst',
                'category' => 'Network activity',
                'value' => '203.0.113.7',
                'to_ids' => true,
                'distribution' => 5,
                'timestamp' => $timestamp,
            ]],
        ]];
    }

    private function newUuid(): string
    {
        return sprintf('%08x-0000-4000-8000-%012x', random_int(0, 0xffffffff), random_int(0, 0xffffffffffff));
    }

    // ----------------------------------------------------------------- _add

    public function testAddCreatesAnEventAndReportsSuccess(): void
    {
        $uuid = $this->newUuid();
        $data = $this->payload($uuid, 'characterize _add', time());

        $result = $this->model('Event')->_add($data, true, $this->adminUser());
        $this->assertNotEmpty($result, '_add must report a result');

        $created = $this->model('Event')->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.uuid' => $uuid],
        ]);
        $this->assertNotEmpty($created, 'the event must exist after _add');
        $this->trackEvent((int)$created['Event']['id']);

        [$ok, $message] = Snapshot::compare('event_add_result', ['result' => $result]);
        $this->assertTrue($ok, $message);
    }

    public function testAddRejectsADuplicateUuid(): void
    {
        $uuid = $this->newUuid();
        $first = $this->payload($uuid, 'characterize _add duplicate', time());
        $this->model('Event')->_add($first, true, $this->adminUser());

        $existing = $this->model('Event')->find('first', [
            'recursive' => -1, 'conditions' => ['Event.uuid' => $uuid],
        ]);
        $this->assertNotEmpty($existing);
        $this->trackEvent((int)$existing['Event']['id']);

        $second = $this->payload($uuid, 'characterize _add duplicate again', time());
        $result = $this->model('Event')->_add($second, true, $this->adminUser());

        // _add signals "this uuid already exists here" by returning the id of
        // the EXISTING event as a bare integer - not an error array, and not
        // the boolean/array shape the success path returns. Asserted as a
        // relationship rather than snapshotted, because a bare scalar carries
        // no key for the normaliser to alias and the value changes every run.
        $this->assertSame(
            (int)$existing['Event']['id'],
            (int)$result,
            '_add on a duplicate uuid should return the existing event id'
        );
        $this->assertCount(
            1,
            $this->model('Event')->find('all', [
                'recursive' => -1, 'conditions' => ['Event.uuid' => $uuid],
            ]),
            'a duplicate uuid must not create a second event'
        );
    }

    // ---------------------------------------------------------------- _edit

    public function testEditWithANewerTimestampApplies(): void
    {
        $uuid = $this->newUuid();
        $base = $this->payload($uuid, 'characterize _edit base', time() - 3600);
        $this->model('Event')->_add($base, true, $this->adminUser());

        $existing = $this->model('Event')->find('first', [
            'recursive' => -1, 'conditions' => ['Event.uuid' => $uuid],
        ]);
        $this->assertNotEmpty($existing);
        $id = $this->trackEvent((int)$existing['Event']['id']);

        $newer = $this->payload($uuid, 'characterize _edit newer', time());
        $result = $this->model('Event')->_edit($newer, $this->adminUser(), $id);

        [$ok, $message] = Snapshot::compare('event_edit_newer', ['result' => $result]);
        $this->assertTrue($ok, $message);
    }

    /**
     * A stale update is reported as an ERROR rather than as a no-op.
     *
     * That wording is what makes sync runs report failures for events that
     * simply had nothing to update - see MISP/MISP#911. Recorded as current
     * behaviour, not endorsed.
     */
    public function testEditWithAnOlderTimestampIsReportedAsAnError(): void
    {
        $uuid = $this->newUuid();
        $base = $this->payload($uuid, 'characterize _edit base', time());
        $this->model('Event')->_add($base, true, $this->adminUser());

        $existing = $this->model('Event')->find('first', [
            'recursive' => -1, 'conditions' => ['Event.uuid' => $uuid],
        ]);
        $this->assertNotEmpty($existing);
        $id = $this->trackEvent((int)$existing['Event']['id']);

        $older = $this->payload($uuid, 'characterize _edit older', time() - 7200);
        $result = $this->model('Event')->_edit($older, $this->adminUser(), $id);

        $this->assertIsArray($result);
        $this->assertArrayHasKey(
            'error',
            $result,
            'a stale update is currently reported as an error; if this changed, MISP/MISP#911 may be fixed'
        );
        [$ok, $message] = Snapshot::compare('event_edit_stale', ['result' => $result]);
        $this->assertTrue($ok, $message);
    }

    // --------------------------------------------------------- freetext

    public function testProcessFreeTextDataResolvesValues(): void
    {
        $id = $this->createEvent('characterize freetext', []);
        $attributes = [
            ['value' => '198.51.100.23', 'type' => 'ip-dst', 'category' => 'Network activity',
             'to_ids' => true, 'distribution' => 5, 'comment' => ''],
            ['value' => 'freetext.example.com', 'type' => 'domain', 'category' => 'Network activity',
             'to_ids' => true, 'distribution' => 5, 'comment' => ''],
        ];
        $result = $this->model('Event')->processFreeTextData($this->adminUser(), $attributes, $id);
        $this->assertNotNull($result);

        $stored = $this->model('MispAttribute')->find('all', [
            'recursive' => -1,
            'conditions' => ['Attribute.event_id' => $id],
            'fields' => ['Attribute.type', 'Attribute.value'],
            'order' => ['Attribute.value' => 'ASC'],
        ]);
        [$ok, $message] = Snapshot::compare('event_freetext_stored', $stored);
        $this->assertTrue($ok, $message);
    }

    // -------------------------------------------------------- quickDelete

    public function testQuickDeleteRemovesTheEvent(): void
    {
        $id = $this->createEvent('characterize quickDelete', [
            ['type' => 'ip-dst', 'value' => '198.51.100.99'],
        ]);
        $event = $this->model('Event')->find('first', [
            'recursive' => -1, 'conditions' => ['Event.id' => $id],
        ]);
        $this->assertNotEmpty($event);

        $this->model('Event')->quickDelete($event);

        $after = $this->model('Event')->find('first', [
            'recursive' => -1, 'conditions' => ['Event.id' => $id],
        ]);
        $this->assertEmpty($after, 'quickDelete must remove the event row');

        $orphans = $this->model('MispAttribute')->find('count', [
            'recursive' => -1, 'conditions' => ['Attribute.event_id' => $id],
        ]);
        $this->assertSame(0, (int)$orphans, 'quickDelete must not leave orphaned attributes');
    }
}
