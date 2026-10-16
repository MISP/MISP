<?php
App::uses('AnalystData', 'Model');
App::uses('RailCard', 'Tools/RailCards');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

/**
 * Rail cards for a note, an opinion or a relationship. $record is the
 * record's own array, with its first level of child analyst data merged in
 * as AnalystDataController::view loads it.
 */
class AnalystDataRailCards
{
    const TYPE_LIMIT = 4;

    /**
     * What the record annotates, as far as the user can see it.
     *
     * @param array $user
     * @param array $record
     * @return array
     */
    public function target(array $user, array $record)
    {
        $type = (string)($record['object_type'] ?? '');
        $isValue = in_array($type, AnalystData::SHA256_TARGETS, true);
        $uuid = (string)($record[AnalystData::addressColumn($type, 'object')] ?? '');
        $resolved = $uuid === '' ? null : $this->resolve($user, $type, $uuid);
        $items = [['label' => __('Type'), 'value' => $type === '' ? __('Unknown') : ($isValue ? __('Value') : $type)]];
        if ($resolved === null) {
            $items[] = ['label' => $isValue ? __('SHA-256') : __('UUID'), 'value' => $uuid];
            return RailCard::status(
                'analyst-target',
                __('Annotates'),
                'fas fa-crosshairs',
                'muted',
                $isValue
                    ? __('This value could not be resolved, so it is shown by the SHA-256 of its text.')
                    : __('What this annotates is not available on this instance.'),
                $items
            );
        }
        foreach ($resolved['items'] as $item) {
            $items[] = $item;
        }
        return RailCard::status(
            'analyst-target',
            __('Annotates'),
            'fas fa-crosshairs',
            'info',
            $resolved['label'],
            $items,
            ['label' => __('Open'), 'href' => $resolved['href'], 'method' => 'get']
        );
    }

    /**
     * @param array $user
     * @param string $type
     * @param string $uuid A uuid, or a SHA-256 for a value
     * @return array|null ['label', 'href', 'items']
     */
    private function resolve(array $user, $type, $uuid)
    {
        switch ($type) {
            case 'AttributeValue':
                $value = ClassRegistry::init('Relationship')->getRelatedElement($user, $type, $uuid);
                if (!isset($value['AttributeValue']['value'])) {
                    return null;
                }
                $text = (string)$value['AttributeValue']['value'];
                return [
                    'label' => mb_strimwidth($text, 0, 160, '…'),
                    'href' => '/values/view/' . ValueUrlTool::encode($text),
                    'items' => [['label' => __('SHA-256'), 'value' => $value['AttributeValue']['sha256']]],
                ];
            case 'Event':
                $Event = ClassRegistry::init('Event');
                $conditions = $Event->createEventConditions($user);
                $conditions['AND'][] = ['Event.uuid' => $uuid];
                $event = $Event->find('first', [
                    'recursive' => -1,
                    'conditions' => $conditions,
                    'fields' => ['Event.id', 'Event.info', 'Event.date'],
                ]);
                if (empty($event)) {
                    return null;
                }
                return [
                    'label' => $event['Event']['info'],
                    'href' => '/events/view/' . $event['Event']['id'],
                    'items' => [['label' => __('Date'), 'value' => $event['Event']['date']]],
                ];
            case 'Attribute':
                $rows = ClassRegistry::init('MispAttribute')->fetchAttributesSimple($user, [
                    'conditions' => ['Attribute.uuid' => $uuid],
                    'fields' => ['Attribute.id', 'Attribute.type', 'Attribute.value', 'Attribute.event_id'],
                ]);
                if (empty($rows)) {
                    return null;
                }
                $a = $rows[0]['Attribute'];
                return [
                    'label' => $a['value'],
                    'href' => '/events/view/' . $a['event_id'] . '/focus:' . $uuid,
                    'items' => array_merge(
                        [['label' => __('Attribute type'), 'value' => $a['type']]],
                        $this->eventItem($a['event_id'])
                    ),
                ];
            case 'Object':
                $rows = ClassRegistry::init('MispObject')->fetchObjectSimple($user, [
                    'conditions' => ['Object.uuid' => $uuid],
                    'fields' => ['Object.id', 'Object.name', 'Object.event_id'],
                ]);
                if (empty($rows)) {
                    return null;
                }
                $o = $rows[0]['Object'];
                return [
                    'label' => __('%s object', $o['name']),
                    'href' => '/events/view/' . $o['event_id'] . '/focus:' . $uuid,
                    'items' => $this->eventItem($o['event_id']),
                ];
            case 'EventReport':
                $Report = ClassRegistry::init('EventReport');
                $conditions = $Report->buildACLConditions($user);
                $conditions['AND'][] = ['EventReport.uuid' => $uuid];
                $report = $Report->find('first', [
                    'recursive' => -1,
                    'conditions' => $conditions,
                    'contain' => ['Event' => ['fields' => ['Event.id']]],
                    'fields' => ['EventReport.id', 'EventReport.name', 'EventReport.event_id'],
                ]);
                if (empty($report)) {
                    return null;
                }
                return [
                    'label' => $report['EventReport']['name'],
                    'href' => '/eventReports/view/' . $report['EventReport']['id'],
                    'items' => $this->eventItem($report['EventReport']['event_id']),
                ];
            case 'GalaxyCluster':
                $cluster = ClassRegistry::init('GalaxyCluster')->fetchGalaxyClusters($user, [
                    'conditions' => ['GalaxyCluster.uuid' => $uuid],
                    'fields' => ['GalaxyCluster.id', 'GalaxyCluster.value', 'GalaxyCluster.galaxy_id'],
                    'contain' => ['Galaxy' => ['fields' => ['Galaxy.name']]],
                    'first' => true,
                ]);
                if (empty($cluster['GalaxyCluster'])) {
                    return null;
                }
                return [
                    'label' => $cluster['GalaxyCluster']['value'],
                    'href' => '/galaxy_clusters/view/' . $cluster['GalaxyCluster']['id'],
                    'items' => [['label' => __('Galaxy'), 'value' => $cluster['Galaxy']['name'] ?? '']],
                ];
            case 'Galaxy':
                $Galaxy = ClassRegistry::init('Galaxy');
                $galaxy = $Galaxy->find('first', [
                    'recursive' => -1,
                    'conditions' => ['AND' => [['Galaxy.uuid' => $uuid], $Galaxy->buildConditions($user)]],
                    'fields' => ['Galaxy.id', 'Galaxy.name'],
                ]);
                return empty($galaxy) ? null : [
                    'label' => $galaxy['Galaxy']['name'],
                    'href' => '/galaxies/view/' . $galaxy['Galaxy']['id'],
                    'items' => [],
                ];
            case 'Note':
            case 'Opinion':
            case 'Relationship':
                $Model = ClassRegistry::init($type);
                $row = $Model->find('first', [
                    'recursive' => -1,
                    'callbacks' => false,
                    'conditions' => ['AND' => [[$Model->alias . '.uuid' => $uuid], $Model->buildConditions($user)]],
                    'fields' => [$Model->alias . '.id'],
                ]);
                return empty($row) ? null : [
                    'label' => __('%s #%s', $type, $row[$Model->alias]['id']),
                    'href' => '/analystData/view/' . $type . '/' . $row[$Model->alias]['id'],
                    'items' => [],
                ];
            case 'Organisation':
                $Organisation = ClassRegistry::init('Organisation');
                $org = $Organisation->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Organisation.uuid' => $uuid],
                    'fields' => ['Organisation.id', 'Organisation.name'],
                ]);
                if (empty($org) || !$Organisation->canSee($user, $org['Organisation']['id'])) {
                    return null;
                }
                return [
                    'label' => $org['Organisation']['name'],
                    'href' => '/organisations/view/' . $org['Organisation']['id'],
                    'items' => [],
                ];
            case 'SharingGroup':
                $SharingGroup = ClassRegistry::init('SharingGroup');
                if (!$SharingGroup->checkIfAuthorised($user, $uuid)) {
                    return null;
                }
                $sg = $SharingGroup->find('first', [
                    'recursive' => -1,
                    'conditions' => ['SharingGroup.uuid' => $uuid],
                    'fields' => ['SharingGroup.id', 'SharingGroup.name'],
                ]);
                return empty($sg) ? null : [
                    'label' => $sg['SharingGroup']['name'],
                    'href' => '/sharing_groups/view/' . $sg['SharingGroup']['id'],
                    'items' => [],
                ];
            case 'Collection':
                $Collection = ClassRegistry::init('Collection');
                $collection = $Collection->find('first', [
                    'recursive' => -1,
                    'conditions' => ['AND' => [['Collection.uuid' => $uuid], $Collection->buildConditions($user['id'])]],
                    'fields' => ['Collection.id', 'Collection.name'],
                ]);
                return empty($collection) ? null : [
                    'label' => $collection['Collection']['name'],
                    'href' => '/collections/view/' . $collection['Collection']['id'],
                    'items' => [],
                ];
        }
        return null;
    }

    /**
     * @param int $eventId an event the user can already see
     * @return array
     */
    private function eventItem($eventId)
    {
        $event = ClassRegistry::init('Event')->find('first', [
            'recursive' => -1,
            'conditions' => ['Event.id' => $eventId],
            'fields' => ['Event.info'],
        ]);
        return empty($event) ? [] : [['label' => __('Event'), 'value' => $event['Event']['info']]];
    }

    /**
     * The notes, opinions and relationships attached to the record.
     *
     * @param array $record
     * @return array
     */
    public function thread(array $record)
    {
        $notes = $record['Note'] ?? [];
        $opinions = $record['Opinion'] ?? [];
        $out = $record['Relationship'] ?? [];
        $in = $record['RelationshipInbound'] ?? [];
        $groups = [];
        if (!empty($notes)) {
            $groups[] = [
                'key' => 'notes',
                'label' => __('Notes'),
                'icon' => 'misp-icon misp-icon-analyst-note misp-simple',
                'color' => 'analystData',
                'count' => count($notes),
            ];
        }
        if (!empty($opinions)) {
            $scores = array_map('intval', array_column($opinions, 'opinion'));
            $agree = count(array_filter($scores, function ($s) { return $s > 50; }));
            $disagree = count(array_filter($scores, function ($s) { return $s < 50; }));
            $neutral = count($scores) - $agree - $disagree;
            $mean = (int)round(array_sum($scores) / max(1, count($scores)));
            $groups[] = [
                'key' => 'opinions',
                'label' => __('Opinions, mean %s/100', $mean),
                'icon' => 'misp-icon misp-icon-analyst-opinion misp-simple',
                'count' => count($opinions),
                'partition' => true,
                'facets' => array_values(array_filter([
                    $agree ? ['label' => __('Agree'), 'count' => $agree, 'tone' => 'ok'] : null,
                    $neutral ? ['label' => __('Neutral'), 'count' => $neutral, 'tone' => 'muted'] : null,
                    $disagree ? ['label' => __('Disagree'), 'count' => $disagree, 'tone' => 'danger'] : null,
                ])),
            ];
        }
        foreach ([['out', __('Relationships'), $out, 'fas fa-arrow-right'], ['in', __('Inbound relationships'), $in, 'fas fa-arrow-left']] as list($key, $label, $relations, $icon)) {
            if (empty($relations)) {
                continue;
            }
            $types = [];
            foreach ($relations as $relation) {
                $t = (string)($relation['relationship_type'] ?? '');
                $types[$t === '' ? __('untyped') : $t] = ($types[$t === '' ? __('untyped') : $t] ?? 0) + 1;
            }
            arsort($types);
            $facets = [];
            foreach (array_slice($types, 0, self::TYPE_LIMIT, true) as $t => $count) {
                $facets[] = ['label' => (string)$t, 'count' => $count];
            }
            $groups[] = [
                'key' => $key,
                'label' => $label,
                'icon' => $icon,
                'color' => 'correlation',
                'count' => count($relations),
                'partition' => true,
                'facets' => $facets,
                'more' => max(0, count($types) - self::TYPE_LIMIT),
            ];
        }
        $total = array_sum(array_column($groups, 'count'));
        return RailCard::inventory(
            'analyst-thread',
            __('Thread'),
            'fas fa-comments',
            ['count' => $total, 'label' => __n('item attached', 'items attached', $total)],
            $groups,
            true,
            [
                'link' => ['label' => __('Thread'), 'href' => '#analyst-thread'],
                'empty' => __('Nothing is attached to it yet.'),
            ]
        );
    }
}
