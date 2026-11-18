<?php
App::uses('EventCardBatch', 'Tools/EventOverview');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');

/**
 * What an event's peek (Elements/Events/peek) shows: the events the reader
 * may see among the given ids, each with its creator and owner orgs, its
 * sharing group's name when the reader is in it, and its card on the events
 * index (context lanes, markings, publish state, distribution), its object
 * and report counts and its extension. A fixed number of queries, whatever
 * the number of ids.
 */
class EventPeekBatch
{
    const FIELDS = [
        'Event.id', 'Event.uuid', 'Event.info', 'Event.date', 'Event.timestamp',
        'Event.published', 'Event.publish_timestamp', 'Event.distribution',
        'Event.sharing_group_id', 'Event.attribute_count', 'Event.extends_uuid',
        'Event.org_id', 'Event.orgc_id',
    ];

    /**
     * @param array $user
     * @param array $ids event ids
     * @return array id => Event, with its Orgc, Org, SharingGroup and EventPeek
     */
    public static function forIds(array $user, array $ids)
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids))));
        if (empty($ids)) {
            return [];
        }
        $Event = ClassRegistry::init('Event');
        $rows = $Event->find('all', [
            'conditions' => ['AND' => [['Event.id' => $ids], $Event->createEventConditions($user)]],
            'fields' => self::FIELDS,
            'recursive' => -1,
        ]);
        if (empty($rows)) {
            return [];
        }

        $orgIds = array_unique(array_merge(
            array_column(array_column($rows, 'Event'), 'orgc_id'),
            array_column(array_column($rows, 'Event'), 'org_id')
        ));
        $orgs = $Event->Orgc->find('all', [
            'conditions' => ['Orgc.id' => $orgIds],
            'fields' => ['Orgc.id', 'Orgc.name', 'Orgc.uuid'],
            'recursive' => -1,
        ]);
        $orgs = array_column(array_column($orgs, 'Orgc'), null, 'id');

        // A sharing group is named only to its members.
        $sgIds = array_intersect(
            array_unique(array_filter(array_column(array_column($rows, 'Event'), 'sharing_group_id'))),
            $Event->SharingGroup->authorizedIds($user)
        );
        $sgNames = empty($sgIds) ? [] : $Event->SharingGroup->find('list', [
            'conditions' => ['SharingGroup.id' => $sgIds],
            'fields' => ['SharingGroup.id', 'SharingGroup.name'],
        ]);

        $events = [];
        foreach ($rows as $row) {
            $e = $row['Event'];
            $sgId = (int)($e['sharing_group_id'] ?? 0);
            $events[(int)$e['id']] = [
                'Event' => $e,
                'Orgc' => $orgs[$e['orgc_id']] ?? [],
                'Org' => $orgs[$e['org_id']] ?? [],
                'SharingGroup' => isset($sgNames[$sgId]) ? ['id' => $sgId, 'name' => $sgNames[$sgId]] : null,
                'EventTag' => [],
            ];
        }

        $eventTags = $Event->EventTag->find('all', [
            'conditions' => ['EventTag.event_id' => array_keys($events)],
            'fields' => ['EventTag.event_id', 'EventTag.tag_id', 'EventTag.local', 'EventTag.relationship_type'],
            'recursive' => -1,
        ]);
        foreach ($eventTags as $eventTag) {
            $events[(int)$eventTag['EventTag']['event_id']]['EventTag'][] = $eventTag['EventTag'];
        }
        $events = $Event->attachTagsToEvents($events);
        $events = ClassRegistry::init('GalaxyCluster')->attachClustersToEventIndex($user, $events, true);
        $events = $Event->attachObjectCountToEvents($events, $Event::INDEX_OBJECT_LIMIT);
        $events = $Event->attachAttributesInObjectsOnlyToEvents($events);
        $events = $Event->EventReport->attachReportCountsToEvents($user, $events);

        $profile = ClassRegistry::init('AnalystProfile')->resolveFor($user);
        $cards = EventCardBatch::cards($events, $user, $profile, ValueLabelPriority::planFor($profile));
        $extension = self::extension($Event, $user, array_column(array_column($events, 'Event'), null, 'id'));

        $peeks = [];
        foreach ($events as $id => $event) {
            $e = $event['Event'];
            $peeks[$id] = $e + [
                'Orgc' => $event['Orgc'],
                'Org' => $event['Org'],
                'SharingGroup' => $event['SharingGroup'],
                'EventPeek' => $cards[$id] + [
                    'object_count' => (int)($e['object_count'] ?? 0),
                    'object_count_more' => !empty($e['object_count_more']),
                    'report_count' => (int)($e['report_count'] ?? 0),
                    'attributes_in_objects_only' => !empty($e['attributes_in_objects_only']),
                    'extends' => $extension['extends'][$id] ?? null,
                    'extended_by' => $extension['extended_by'][$e['uuid']] ?? 0,
                ],
            ];
        }
        return $peeks;
    }

    /**
     * What each event extends (id and info when the reader may see it) and
     * how many visible events extend it.
     *
     * @param Event $Event
     * @param array $user
     * @param array $events Event rows, keyed by id
     * @return array extends: id => [id, info, uuid]; extended_by: uuid => count
     */
    private static function extension($Event, array $user, array $events)
    {
        $parentUuids = array_values(array_unique(array_filter(array_column($events, 'extends_uuid'))));
        $parents = empty($parentUuids) ? [] : array_column(
            array_column($Event->fetchSimpleEvents($user, ['conditions' => ['Event.uuid' => $parentUuids]]), 'Event'),
            null,
            'uuid'
        );
        $extends = [];
        foreach ($events as $id => $e) {
            if (!empty($e['extends_uuid'])) {
                $parent = $parents[$e['extends_uuid']] ?? null;
                $extends[$id] = [
                    'id' => $parent ? (int)$parent['id'] : null,
                    'info' => $parent['info'] ?? null,
                    'uuid' => $e['extends_uuid'],
                ];
            }
        }
        $children = $Event->find('all', [
            'conditions' => ['AND' => [
                ['Event.extends_uuid' => array_column($events, 'uuid')],
                $Event->createEventConditions($user),
            ]],
            'fields' => ['Event.extends_uuid', 'COUNT(*) AS children'],
            'group' => ['Event.extends_uuid'],
            'recursive' => -1,
        ]);
        $extendedBy = [];
        foreach ($children as $child) {
            $extendedBy[$child['Event']['extends_uuid']] = (int)$child[0]['children'];
        }
        return ['extends' => $extends, 'extended_by' => $extendedBy];
    }
}
