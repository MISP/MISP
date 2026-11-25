<?php
App::uses('AppModel', 'Model');
App::uses('AnalystGraphDocumentTool', 'Tools');
App::uses('CakeText', 'Utility');
App::uses('CollectionElement', 'Model');
App::uses('DistributionLevel', 'Tools');
App::uses('ValueNewEventTool', 'Tools/ValueIntelligence');
App::uses('ValueTypeGuessTool', 'Tools/ValueIntelligence');

/**
 * What a selection of a collection becomes in an event. A value or an object
 * MISP does not hold becomes an attribute or an object of the event and takes
 * its member's place; an attribute or an object from another event is copied,
 * never shared wider than its source; a cluster tags the event; an event is
 * linked to it.
 */
class CollectionToEvent extends AppModel
{
    public $useTable = false;

    /** Items one plan or one event takes. */
    const ITEM_LIMIT = 500;

    const LINK = 'related-to';

    const COMMENT_BYTES = 65535;

    /** Offered for a value whenever it validates as one, after the parser's reading. */
    const COMMON_TYPES = [
        'domain', 'hostname', 'url', 'ip-dst', 'ip-src', 'email', 'md5', 'sha1', 'sha256',
        'filename', 'AS', 'mutex', 'regkey',
    ];

    /** What an item may say of the attribute it becomes. */
    const EDITS = ['attribute_type', 'category', 'to_ids', 'comment', 'node'];

    private $models = [];

    private function model($alias)
    {
        if (!isset($this->models[$alias])) {
            $this->models[$alias] = ClassRegistry::init($alias);
        }
        return $this->models[$alias];
    }

    /**
     * What each item would become.
     *
     * @param array $user
     * @param array $collection Collection::workspaceSummaries()'s
     * @param array $items As addItems takes them, or {key, ...edits}
     * @param array $target {event: an event row the user may modify} or a new
     *   event's {distribution, sharing_group_id}
     * @param array $rights {tag: may tag the event, link: may write analyst data}
     * @return array {target, rows, type_info, narrower, counts}
     */
    public function plan(array $user, array $collection, array $items, array $target, array $rights)
    {
        $rows = $this->rows($user, $collection, $items, $target, $rights);
        return [
            'target' => $this->targetSummary($target),
            'rows' => array_map([$this, 'publicRow'], $rows),
            'type_info' => $this->typeInfo($rows),
            'narrower' => $this->narrower($user, $rows, $target),
            'counts' => self::counts($rows),
        ];
    }

    /**
     * Make the event, or fill one, then put what was made in the places of
     * the members MISP did not hold, in the collection and on its graph.
     *
     * @param array $user
     * @param array $collection Collection::workspaceSummaries()'s
     * @param array $items
     * @param array $target {event: a row the user may modify} or {fields:
     *   a new event's, as NewEventFormTool::fields() gives them}
     * @param array $rights {tag, link}
     * @param array|null $graph The workspace graph the user may write, {id, uuid}
     * @return array {errors} when nothing was made; else {event, created,
     *   rows, replaced, graph, counts, message}
     */
    public function apply(array $user, array $collection, array $items, array $target, array $rights, $graph = null)
    {
        $level = isset($target['event'])
            ? [(int)$target['event']['Event']['distribution'], $target['event']['Event']['sharing_group_id']]
            : [(int)$target['fields']['distribution'], $target['fields']['sharing_group_id'] ?? null];
        $rows = $this->rows($user, $collection, $items, isset($target['event']) ? $target : [
            'distribution' => $level[0], 'sharing_group_id' => $level[1],
        ], $rights);
        $rows = $this->withEdits($rows);
        $going = array_filter($rows, function ($row) {
            return $row['becomes'] !== null && !isset($row['state']);
        });
        if (empty($going)) {
            return ['errors' => ['items' => __('Nothing in the selection can go into an event.')]];
        }

        $Event = $this->model('Event');
        $created = false;
        if (isset($target['event'])) {
            $eventId = (int)$target['event']['Event']['id'];
        } else {
            $new = ['Event' => $target['fields']];
            $createdId = 0;
            $validationErrors = [];
            $result = $Event->_add($new, false, $user, 0, null, false, null, $createdId, $validationErrors);
            if ($result !== true) {
                return ['errors' => ['event' => __('The event could not be created.')]];
            }
            $eventId = (int)$Event->id;
            $created = true;
        }
        $event = $Event->fetchSimpleEvent($user, $eventId);

        $message = $this->saveRecords($user, $event, $rows);
        $this->attachClusters($user, $event, $rows);
        $this->linkEvents($user, $event, $rows);
        list($replaced, $nodes) = $this->swap($user, $collection, $rows);
        $graphReport = $graph === null || empty($nodes) ? null : $this->rewriteGraph($graph, $nodes);

        foreach ($rows as $i => $row) {
            if (!isset($rows[$i]['state'])) {
                $rows[$i]['state'] = $row['becomes'] === null ? 'skipped' : 'failed';
            }
        }
        return [
            'event' => [
                'id' => $eventId,
                'uuid' => $event['Event']['uuid'],
                'info' => $event['Event']['info'],
            ],
            'created' => $created,
            'rows' => array_map([$this, 'publicRow'], $rows),
            'replaced' => (object)$replaced,
            'graph' => $graphReport,
            'counts' => self::states($rows),
            'message' => $message,
        ];
    }

    /**
     * The events the user may modify for the selection to go into: those the
     * collection holds, directly or through its attributes and objects, in
     * the order their first member joined; then the newest, or those matching
     * $q by id, uuid or info.
     *
     * @param array $user
     * @param array $collection
     * @param string $q
     * @param int $limit
     * @return array {tied, found}
     */
    public function choices(array $user, array $collection, $q = '', $limit = 20)
    {
        $modify = $this->modifiableConditions($user);
        if ($modify === null) {
            return ['tied' => [], 'found' => []];
        }
        $tiedIds = $this->tiedEventIds($user, (int)$collection['id']);
        $tied = [];
        if (!empty($tiedIds)) {
            $rows = $this->eventRows($user, $modify, ['Event.id' => $tiedIds], null, count($tiedIds));
            $byId = [];
            foreach ($rows as $row) {
                $byId[(int)$row['id']] = $row;
            }
            foreach ($tiedIds as $id) {
                if (isset($byId[$id])) {
                    $tied[] = $byId[$id];
                }
                if (count($tied) >= $limit) {
                    break;
                }
            }
        }
        $q = trim((string)$q);
        $match = [];
        if ($q !== '') {
            if (ctype_digit($q)) {
                $match['OR'][] = ['Event.id' => (int)$q];
            }
            if (Validation::uuid($q)) {
                $match['OR'][] = ['Event.uuid' => array_values(array_unique([$q, strtolower($q), strtoupper($q)]))];
            }
            $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], mb_strtolower($q)) . '%';
            $match['OR'][] = ['LOWER(Event.info) LIKE' => $like];
        }
        $found = $this->eventRows($user, $modify, $match, ['Event.id' => 'DESC'], $limit);
        return ['tied' => $tied, 'found' => $found];
    }

    /**
     * @param array $user
     * @param array $collection
     * @param array $items
     * @param array $target
     * @param array $rights
     * @return array One row per item, in order; private fields start with _
     */
    private function rows(array $user, array $collection, array $items, array $target, array $rights)
    {
        $level = $this->levelOf($target);
        $eventId = isset($target['event']) ? (int)$target['event']['Event']['id'] : null;
        $eventUuid = isset($target['event']) ? strtolower($target['event']['Event']['uuid']) : null;

        $rows = [];
        $wanted = [];
        foreach (array_values($items) as $i => $item) {
            $address = is_array($item) && is_string($item['key'] ?? null) ? $item['key'] : $item;
            $named = CollectionElement::itemTarget($address);
            if ($named === null || isset($named['error'])) {
                $rows[] = self::row($named['key'] ?? null, null, null, $named['error'] ?? __('Not a record a collection can hold.'));
                continue;
            }
            if (isset($wanted[$named['key']])) {
                continue;
            }
            $named['edit'] = is_array($item) ? array_intersect_key($item, array_flip(self::EDITS)) : [];
            $wanted[$named['key']] = count($rows);
            $rows[] = ['_target' => $named];
        }
        $members = $this->members((int)$collection['id'], $wanted, $rows);

        $byType = [];
        foreach ($wanted as $key => $at) {
            $byType[$rows[$at]['_target']['element_type']][$key] = $at;
        }
        foreach ($byType as $type => $keys) {
            switch ($type) {
                case 'AttributeValue':
                    $this->valueRows($user, $rows, $keys, $members);
                    break;
                case 'StandaloneObject':
                    $this->standaloneRows($rows, $keys, $members);
                    break;
                case 'Attribute':
                    $this->attributeRows($user, $rows, $keys, $members, $level, $eventId);
                    break;
                case 'Object':
                    $this->objectRows($user, $rows, $keys, $members, $level, $eventId);
                    break;
                case 'GalaxyCluster':
                    $this->clusterRows($user, $rows, $keys, $members, $eventId, !empty($rights['tag']));
                    break;
                case 'Event':
                    $this->eventLinkRows($user, $rows, $keys, $members, $level, $eventUuid, !empty($rights['link']));
                    break;
            }
        }
        foreach ($rows as $i => $row) {
            if (!array_key_exists('becomes', $row)) {
                $rows[$i] = self::row($row['_target']['key'], null, null, __('Not found or not authorised.')) + $row;
            }
        }
        return $rows;
    }

    /**
     * @param array $user
     * @param array $rows
     * @param array $keys key => row index
     * @param array $members key => element
     */
    private function valueRows(array $user, array &$rows, array $keys, array $members)
    {
        $unread = [];
        foreach ($keys as $key => $at) {
            $text = $members[$key]['element_value'] ?? $rows[$at]['_target']['text'] ?? null;
            if ($text === null && isset($members[$key])) {
                $unread[$key] = $members[$key];
            }
        }
        $texts = [];
        if (!empty($unread)) {
            foreach ($this->model('CollectionElement')->attachTargets($user, array_values($unread)) as $element) {
                if (isset($element['AttributeValue']['value'])) {
                    $texts['Value:' . strtolower($element['element_sha256'])] = $element['AttributeValue']['value'];
                }
            }
        }
        foreach ($keys as $key => $at) {
            $target = $rows[$at]['_target'];
            $member = $members[$key] ?? null;
            $text = $member['element_value'] ?? $target['text'] ?? $texts[$key] ?? null;
            if ($text === null) {
                $rows[$at] = self::row($key, $member ? 'value' : 'answer', null, __('Send the value itself: no attribute you can see holds this SHA-256.')) + $rows[$at];
                continue;
            }
            $types = $this->typesFor($text, $target['edit']['attribute_type'] ?? null);
            $type = $types[0];
            $row = self::row($key, $member ? 'value' : 'answer', 'attribute') + [
                'value' => $text,
                'types' => $types,
                'type' => $type,
                'category' => $this->categoriesFor($type)[0] ?? '',
                'to_ids' => $this->typeIds($type),
                'comment' => '',
            ];
            $rows[$at] = self::placed($row, $member, $target) + $rows[$at];
        }
    }

    /**
     * @param array $rows
     * @param array $keys
     * @param array $members
     */
    private function standaloneRows(array &$rows, array $keys, array $members)
    {
        $StandaloneObject = $this->model('StandaloneObject');
        $held = [];
        foreach ($keys as $key => $at) {
            if (isset($members[$key])) {
                $held[] = $rows[$at]['_target']['address'];
            }
        }
        $records = $StandaloneObject->records($held);
        foreach ($keys as $key => $at) {
            $target = $rows[$at]['_target'];
            $member = $members[$key] ?? null;
            $record = $member ? ($records[$target['address']] ?? null) : null;
            if ($record === null && !$member && isset($target['build']['content'])) {
                $errors = [];
                $record = $StandaloneObject->fromAnswer($target['build']['module'], $target['build']['content'], $errors);
            }
            if ($record === null) {
                $rows[$at] = self::row($key, $member ? 'standalone' : 'answer', null, $member ? __('Not found or not authorised.') : __('Not in this collection.')) + $rows[$at];
                continue;
            }
            $template = $this->model('ObjectTemplate')->findForObject($record['name'], $record['template_uuid'], $record['template_version']);
            $row = self::row($key, $member ? 'standalone' : 'answer', $template === null ? null : 'object',
                $template === null ? __('No “%s” object template on this instance: it stays as it is.', $record['name']) : null
            ) + self::objectFields($record['name'], $template, $record['meta_category'], $record['comment'], $record['attributes']);
            $rows[$at] = self::placed($row, $member, $target) + ['_record' => $record] + $rows[$at];
        }
    }

    /**
     * @param array $user
     * @param array $rows
     * @param array $keys
     * @param array $members
     * @param array $level
     * @param int|null $eventId
     */
    private function attributeRows(array $user, array &$rows, array $keys, array $members, array $level, $eventId)
    {
        $uuids = [];
        foreach ($keys as $key => $at) {
            $uuids[] = $rows[$at]['_target']['address'];
            $uuids[] = strtoupper($rows[$at]['_target']['address']);
        }
        $found = $this->model('MispAttribute')->fetchAttributesSimple($user, [
            'conditions' => ['Attribute.uuid' => $uuids, 'Attribute.deleted' => 0],
            'fields' => [
                'Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.value',
                'Attribute.to_ids', 'Attribute.comment', 'Attribute.distribution', 'Attribute.sharing_group_id',
                'Attribute.event_id', 'Attribute.object_id',
                'Event.id', 'Event.info', 'Event.distribution', 'Event.sharing_group_id',
                'Object.id', 'Object.distribution', 'Object.sharing_group_id',
            ],
        ]);
        $byUuid = [];
        foreach ($found as $row) {
            $byUuid[strtolower($row['Attribute']['uuid'])] = $row;
        }
        $groups = $this->groupNames($found);
        foreach ($keys as $key => $at) {
            $source = $byUuid[$rows[$at]['_target']['address']] ?? null;
            if ($source === null) {
                continue;
            }
            $attribute = $source['Attribute'];
            $reach = self::reach($source);
            $same = $eventId !== null && (int)$attribute['event_id'] === $eventId;
            $row = self::row($key, 'attribute', $same ? null : 'attribute', $same ? __('Already in this event.') : null) + [
                'member' => isset($members[$key]),
                'value' => $attribute['value'],
                'type' => $attribute['type'],
                'category' => $attribute['category'],
                'to_ids' => !empty($attribute['to_ids']),
                'comment' => (string)$attribute['comment'],
                'source' => [
                    'event' => ['id' => (int)$source['Event']['id'], 'info' => $source['Event']['info']],
                    'reach' => self::reachOut($reach, $groups),
                ],
                'capped' => !$same && DistributionLevel::reachesFewer($reach, $level),
            ];
            $rows[$at] = $row + ['_reach' => $reach] + $rows[$at];
        }
    }

    /**
     * @param array $user
     * @param array $rows
     * @param array $keys
     * @param array $members
     * @param array $level
     * @param int|null $eventId
     */
    private function objectRows(array $user, array &$rows, array $keys, array $members, array $level, $eventId)
    {
        $uuids = [];
        foreach ($keys as $key => $at) {
            $uuids[] = $rows[$at]['_target']['address'];
            $uuids[] = strtoupper($rows[$at]['_target']['address']);
        }
        $found = $this->model('MispObject')->fetchObjectSimple($user, [
            'conditions' => ['Object.uuid' => $uuids, 'Object.deleted' => 0],
            'fields' => [
                'Object.id', 'Object.uuid', 'Object.name', 'Object.meta-category', 'Object.comment',
                'Object.template_uuid', 'Object.template_version', 'Object.distribution',
                'Object.sharing_group_id', 'Object.event_id',
            ],
            'contain' => ['Event' => ['fields' => ['id', 'info', 'distribution', 'sharing_group_id']]],
        ]);
        $byUuid = [];
        $ids = [];
        foreach ($found as $row) {
            $byUuid[strtolower($row['Object']['uuid'])] = $row;
            $ids[] = (int)$row['Object']['id'];
        }
        $attributes = [];
        if (!empty($ids)) {
            $read = $this->model('MispAttribute')->fetchAttributesSimple($user, [
                'conditions' => ['Attribute.object_id' => $ids, 'Attribute.deleted' => 0],
                'fields' => [
                    'Attribute.id', 'Attribute.object_id', 'Attribute.object_relation', 'Attribute.type',
                    'Attribute.category', 'Attribute.value', 'Attribute.to_ids', 'Attribute.comment',
                    'Attribute.distribution', 'Attribute.sharing_group_id',
                    'Event.id', 'Event.distribution', 'Event.sharing_group_id',
                    'Object.id', 'Object.distribution', 'Object.sharing_group_id',
                ],
                'order' => ['Attribute.id' => 'ASC'],
            ]);
            foreach ($read as $row) {
                $attributes[(int)$row['Attribute']['object_id']][] = $row;
            }
        }
        $groups = $this->groupNames(array_merge($found, ...array_values($attributes ?: [[]])));
        foreach ($keys as $key => $at) {
            $source = $byUuid[$rows[$at]['_target']['address']] ?? null;
            if ($source === null) {
                continue;
            }
            $object = $source['Object'];
            $reach = self::reach(['Event' => $source['Event'], 'Object' => $object]);
            $same = $eventId !== null && (int)$object['event_id'] === $eventId;
            $inside = [];
            foreach ($attributes[(int)$object['id']] ?? [] as $row) {
                $attributeReach = self::reach($row);
                $inside[] = [
                    'relation' => (string)$row['Attribute']['object_relation'],
                    'type' => $row['Attribute']['type'],
                    'value' => $row['Attribute']['value'],
                    'category' => $row['Attribute']['category'],
                    'to_ids' => !empty($row['Attribute']['to_ids']),
                    'comment' => (string)$row['Attribute']['comment'],
                    'capped' => !$same && DistributionLevel::reachesFewer($attributeReach, $level),
                    '_reach' => $attributeReach,
                ];
            }
            $template = $this->model('ObjectTemplate')->findForObject($object['name'], $object['template_uuid'], $object['template_version']);
            $reason = $same ? __('Already in this event.') : null;
            if ($reason === null && empty($inside)) {
                $reason = __('None of its attributes is yours to read.');
            }
            if ($reason === null && $template === null) {
                $reason = __('No “%s” object template on this instance: it stays as it is.', $object['name']);
            }
            $row = self::row($key, 'object', $reason === null ? 'object' : null, $reason)
                + ['member' => isset($members[$key])]
                + self::objectFields($object['name'], $template, $object['meta-category'], (string)$object['comment'], $inside)
                + [
                    'source' => [
                        'event' => ['id' => (int)$source['Event']['id'], 'info' => $source['Event']['info']],
                        'reach' => self::reachOut($reach, $groups),
                    ],
                    'capped' => !$same && DistributionLevel::reachesFewer($reach, $level),
                ];
            $rows[$at] = $row + ['_reach' => $reach] + $rows[$at];
        }
    }

    /**
     * @param array $user
     * @param array $rows
     * @param array $keys
     * @param array $members
     * @param int|null $eventId
     * @param bool $mayTag
     */
    private function clusterRows(array $user, array &$rows, array $keys, array $members, $eventId, $mayTag)
    {
        $uuids = [];
        foreach ($keys as $key => $at) {
            $uuids[] = $rows[$at]['_target']['address'];
            $uuids[] = strtoupper($rows[$at]['_target']['address']);
        }
        $found = $this->model('GalaxyCluster')->fetchGalaxyClusters($user, [
            'conditions' => ['GalaxyCluster.uuid' => $uuids],
            'fields' => ['GalaxyCluster.id', 'GalaxyCluster.uuid', 'GalaxyCluster.value', 'GalaxyCluster.tag_name'],
            'contain' => ['Galaxy' => ['fields' => ['Galaxy.name', 'Galaxy.local_only']]],
        ]);
        $byUuid = [];
        foreach ($found as $row) {
            $byUuid[strtolower($row['GalaxyCluster']['uuid'])] = $row;
        }
        $attached = [];
        if ($eventId !== null && !empty($found)) {
            $Tag = ClassRegistry::init('Tag');
            $tagIds = $Tag->find('list', [
                'recursive' => -1,
                'fields' => ['Tag.id', 'Tag.name'],
                'conditions' => ['Tag.name' => array_values(array_unique(Hash::extract($found, '{n}.GalaxyCluster.tag_name')))],
            ]);
            if (!empty($tagIds)) {
                $on = $Tag->EventTag->find('column', [
                    'fields' => ['EventTag.tag_id'],
                    'conditions' => ['EventTag.event_id' => $eventId, 'EventTag.tag_id' => array_keys($tagIds)],
                ]);
                foreach ($on as $tagId) {
                    $attached[$tagIds[$tagId]] = true;
                }
            }
        }
        foreach ($keys as $key => $at) {
            $source = $byUuid[$rows[$at]['_target']['address']] ?? null;
            if ($source === null) {
                continue;
            }
            $cluster = $source['GalaxyCluster'];
            $reason = null;
            if (!$mayTag) {
                $reason = __('Your role cannot tag events.');
            } elseif (isset($attached[$cluster['tag_name']])) {
                $reason = __('Already on this event.');
            }
            $rows[$at] = self::row($key, 'cluster', $reason === null ? 'tag' : null, $reason) + [
                'member' => isset($members[$key]),
                'value' => $cluster['value'],
                'galaxy' => $source['GalaxyCluster']['Galaxy']['name'] ?? $source['Galaxy']['name'] ?? '',
                'tag' => $cluster['tag_name'],
                'local' => !empty($source['GalaxyCluster']['Galaxy']['local_only'] ?? $source['Galaxy']['local_only'] ?? false),
                '_cluster_id' => (int)$cluster['id'],
            ] + $rows[$at];
        }
    }

    /**
     * @param array $user
     * @param array $rows
     * @param array $keys
     * @param array $members
     * @param array $level
     * @param string|null $eventUuid
     * @param bool $mayLink
     */
    private function eventLinkRows(array $user, array &$rows, array $keys, array $members, array $level, $eventUuid, $mayLink)
    {
        $uuids = [];
        foreach ($keys as $key => $at) {
            $uuids[] = $rows[$at]['_target']['address'];
            $uuids[] = strtoupper($rows[$at]['_target']['address']);
        }
        $Event = $this->model('Event');
        $conditions = $Event->createEventConditions($user);
        $conditions['AND'][] = ['Event.uuid' => $uuids];
        $found = $Event->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Event.id', 'Event.uuid', 'Event.info', 'Event.distribution', 'Event.sharing_group_id'],
        ]);
        $byUuid = [];
        foreach ($found as $row) {
            $byUuid[strtolower($row['Event']['uuid'])] = $row['Event'];
        }
        $linked = [];
        if ($eventUuid !== null && !empty($byUuid)) {
            $existing = ClassRegistry::init('Relationship')->find('column', [
                'fields' => ['Relationship.related_object_uuid'],
                'conditions' => [
                    'Relationship.object_type' => 'Event',
                    'Relationship.object_uuid' => [$eventUuid, strtoupper($eventUuid)],
                    'Relationship.related_object_type' => 'Event',
                    'Relationship.related_object_uuid' => array_merge(array_keys($byUuid), array_map('strtoupper', array_keys($byUuid))),
                    'Relationship.relationship_type' => self::LINK,
                ],
            ]);
            foreach ($existing as $uuid) {
                $linked[strtolower($uuid)] = true;
            }
        }
        foreach ($keys as $key => $at) {
            $address = $rows[$at]['_target']['address'];
            $event = $byUuid[$address] ?? null;
            if ($event === null) {
                continue;
            }
            $reason = null;
            if ($address === $eventUuid) {
                $reason = __('This is the event.');
            } elseif (!$mayLink) {
                $reason = __('Your role cannot add relationships.');
            } elseif (isset($linked[$address])) {
                $reason = __('Already linked.');
            }
            $reach = [(int)$event['distribution'], $event['sharing_group_id']];
            $rows[$at] = self::row($key, 'event', $reason === null ? 'link' : null, $reason) + [
                'member' => isset($members[$key]),
                'id' => (int)$event['id'],
                'info' => $event['info'],
                'relationship' => self::LINK,
                'capped' => DistributionLevel::reachesFewer($reach, $level),
                '_reach' => $reach,
            ] + $rows[$at];
        }
    }

    /**
     * Value rows take the type, category, IDS flag and comment their item
     * names; an edit that does not fit fails the row.
     *
     * @param array $rows
     * @return array
     */
    private function withEdits(array $rows)
    {
        $definitions = $this->model('MispAttribute')->typeDefinitions;
        foreach ($rows as $i => $row) {
            if ($row['becomes'] !== 'attribute' || !in_array($row['kind'], ['value', 'answer'], true)) {
                continue;
            }
            $edit = $row['_target']['edit'] ?? [];
            if (isset($edit['attribute_type'])) {
                $type = $edit['attribute_type'];
                if (!is_string($type) || !isset($definitions[$type]) || strpos($type, '|') !== false || !ValueTypeGuessTool::accepts($type, $row['value'])) {
                    $rows[$i]['state'] = 'failed';
                    $rows[$i]['message'] = __('This value cannot be saved as %s.', is_scalar($type) ? $type : '?');
                    continue;
                }
                if ($type !== $row['type']) {
                    $rows[$i]['type'] = $type;
                    $rows[$i]['category'] = $this->categoriesFor($type)[0] ?? '';
                    $rows[$i]['to_ids'] = $this->typeIds($type);
                }
            }
            if (isset($edit['category'])) {
                if (!is_string($edit['category']) || !in_array($edit['category'], $this->categoriesFor($rows[$i]['type']), true)) {
                    $rows[$i]['state'] = 'failed';
                    $rows[$i]['message'] = __('%s is not a category for %s.', is_scalar($edit['category']) ? $edit['category'] : '?', $rows[$i]['type']);
                    continue;
                }
                $rows[$i]['category'] = $edit['category'];
            }
            if (array_key_exists('to_ids', $edit)) {
                $rows[$i]['to_ids'] = !empty($edit['to_ids']);
            }
            if (isset($edit['comment'])) {
                if (!is_string($edit['comment']) || strlen($edit['comment']) > self::COMMENT_BYTES) {
                    $rows[$i]['state'] = 'failed';
                    $rows[$i]['message'] = __('A comment is text of at most %s bytes.', self::COMMENT_BYTES);
                    continue;
                }
                $rows[$i]['comment'] = trim($edit['comment']);
            }
        }
        return $rows;
    }

    /**
     * Attributes and objects through saveEnrichmentResults(): a copy capped at
     * its source's sharing.
     *
     * @param array $user
     * @param array $event
     * @param array $rows
     * @return string What the save said
     */
    private function saveRecords(array $user, array $event, array &$rows)
    {
        $payload = ['Attribute' => [], 'Object' => []];
        $sent = [];
        foreach ($rows as $i => $row) {
            if (isset($row['state']) || !in_array($row['becomes'], ['attribute', 'object'], true)) {
                continue;
            }
            $uuid = CakeText::uuid();
            $sent[$uuid] = $i;
            $cap = isset($row['_reach']) ? self::capOf($row['_reach']) : null;
            if ($row['becomes'] === 'attribute') {
                $payload['Attribute'][] = [
                    'uuid' => $uuid,
                    'type' => $row['type'],
                    'category' => $row['category'],
                    'value' => (string)$row['value'],
                    'to_ids' => !empty($row['to_ids']),
                    'comment' => (string)$row['comment'],
                ] + ($cap === null ? [] : ['cap' => $cap]);
                continue;
            }
            $attributes = [];
            foreach ($row['attributes'] as $attribute) {
                $attributes[] = [
                    'uuid' => CakeText::uuid(),
                    'object_relation' => $attribute['relation'],
                    'type' => $attribute['type'],
                    'category' => (string)($attribute['category'] ?? ''),
                    'value' => (string)$attribute['value'],
                    'to_ids' => !empty($attribute['to_ids']),
                    'comment' => (string)($attribute['comment'] ?? ''),
                ] + (isset($attribute['_reach']) ? ['cap' => self::capOf($attribute['_reach'])] : []);
            }
            $payload['Object'][] = [
                'uuid' => $uuid,
                'name' => $row['name'],
                'template_uuid' => $row['template']['uuid'],
                'template_version' => $row['template']['version'],
                'comment' => (string)$row['comment'],
                'Attribute' => $attributes,
            ] + ($cap === null ? [] : ['cap' => $cap]);
        }
        if (empty($sent)) {
            return '';
        }
        $saved = $this->model('Event')->saveEnrichmentResults($user, $event, $payload);
        foreach ($sent as $uuid => $i) {
            $result = $saved['results'][$uuid] ?? ['state' => 'failed'];
            $rows[$i]['state'] = in_array($result['state'], ['saved', 'existing'], true) ? $result['state'] : 'failed';
            if (isset($result['uuid'])) {
                $rows[$i]['record'] = ($rows[$i]['becomes'] === 'object' ? 'Object' : 'Attribute') . ':' . strtolower($result['uuid']);
            }
            if (isset($result['message'])) {
                $rows[$i]['message'] = $result['message'];
            }
        }
        return (string)($saved['message'] ?? '');
    }

    /**
     * @param array $user
     * @param array $event
     * @param array $rows
     */
    private function attachClusters(array $user, array $event, array &$rows)
    {
        $Galaxy = null;
        foreach ($rows as $i => $row) {
            if (isset($row['state']) || $row['becomes'] !== 'tag') {
                continue;
            }
            $Galaxy = $Galaxy ?: ClassRegistry::init('Galaxy');
            try {
                $said = $Galaxy->attachCluster($user, 'event', $event, $row['_cluster_id'], $row['local']);
            } catch (Exception $e) {
                $said = $e->getMessage();
            }
            if ($said === 'Cluster attached.') {
                $rows[$i]['state'] = 'saved';
            } elseif ($said === 'Cluster already attached.') {
                $rows[$i]['state'] = 'existing';
            } else {
                $rows[$i]['state'] = 'failed';
                $rows[$i]['message'] = (string)$said;
            }
        }
    }

    /**
     * A related-to relationship from the event to each event linked, shared
     * as the event, and no wider than the event it names.
     *
     * @param array $user
     * @param array $event
     * @param array $rows
     */
    private function linkEvents(array $user, array $event, array &$rows)
    {
        $level = [(int)$event['Event']['distribution'], $event['Event']['sharing_group_id']];
        $Relationship = null;
        foreach ($rows as $i => $row) {
            if (isset($row['state']) || $row['becomes'] !== 'link') {
                continue;
            }
            if ($Relationship === null) {
                $Relationship = ClassRegistry::init('Relationship');
                $Relationship->current_user = $user;
            }
            $sharing = DistributionLevel::reachesFewer($row['_reach'], $level) ? $row['_reach'] : $level;
            $Relationship->create();
            $saved = $Relationship->save(['Relationship' => [
                'object_type' => 'Event',
                'object_uuid' => $event['Event']['uuid'],
                'related_object_type' => 'Event',
                'related_object_uuid' => $row['_target']['address'],
                'relationship_type' => self::LINK,
                'distribution' => (int)$sharing[0],
                'sharing_group_id' => (int)$sharing[0] === 4 ? $sharing[1] : null,
            ]]);
            if ($saved) {
                $rows[$i]['state'] = 'saved';
                $rows[$i]['record'] = 'Relationship:' . strtolower((string)$Relationship->field('uuid', ['Relationship.id' => $Relationship->id]));
            } else {
                $rows[$i]['state'] = 'failed';
                $rows[$i]['message'] = implode(' ', Hash::flatten($Relationship->validationErrors));
            }
        }
    }

    /**
     * Each record made for a member MISP did not hold takes its place: the
     * record joins with the member's why and origin, the member leaves. A
     * record made for an answer joins with the answer's origin.
     *
     * @param array $user
     * @param array $collection
     * @param array $rows
     * @return array [old key => new key, graph node key => the record's node]
     */
    private function swap(array $user, array $collection, array &$rows)
    {
        $CollectionElement = $this->model('CollectionElement');
        $CollectionElement->current_user = $user;
        $replaced = [];
        $nodes = [];
        foreach ($rows as $i => $row) {
            if (!in_array($row['state'] ?? null, ['saved', 'existing'], true) || !isset($row['record'])
                || (empty($row['gives_way']) && empty($row['joins']))
            ) {
                continue;
            }
            list($type, $uuid) = explode(':', $row['record'], 2);
            $element = $row['_element'] ?? null;
            $origin = $element['origin'] ?? (isset($row['_target']['origin']) ? json_encode($row['_target']['origin'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null);
            $CollectionElement->create();
            try {
                $joined = (bool)$CollectionElement->save(['CollectionElement' => [
                    'collection_id' => $collection['id'],
                    'element_type' => $type,
                    'element_uuid' => $uuid,
                    'description' => (string)($element['description'] ?? ''),
                    'origin' => $origin,
                ]]);
            } catch (PDOException $e) {
                if (!CollectionElement::isDuplicate($e)) {
                    throw $e;
                }
                $joined = true;
            }
            if (!$joined) {
                $rows[$i]['message'] = __('Made, but it could not join the collection.');
                continue;
            }
            if ($element !== null) {
                $CollectionElement->delete($element['id']);
            }
            $replaced[$row['key']] = $row['record'];
            $rows[$i]['replaced'] = true;
            $record = ['type' => $type, 'uuid' => $uuid];
            foreach (self::nodeKeysOf($row) as $key) {
                $nodes[$key] = $record;
            }
        }
        return [$replaced, $nodes];
    }

    /**
     * @param array $graph {id, uuid}
     * @param array $nodes graph node key => the record's node
     * @return array {uuid, written, revision, replaced}
     */
    private function rewriteGraph(array $graph, array $nodes)
    {
        $report = ['replaced' => []];
        $result = $this->model('Graph')->writeContent($graph['id'], function (array $document) use ($nodes, &$report) {
            list($document, $report) = AnalystGraphDocumentTool::replaceNodes($document, $nodes);
            return empty($report['replaced']) ? null : $document;
        });
        return [
            'uuid' => $graph['uuid'],
            'written' => $result['status'] === 'saved',
            'revision' => $result['revision'],
            'replaced' => (object)$report['replaced'],
        ];
    }

    /**
     * Where a row's item may sit on the graph: the node the client names,
     * and the ones the member or answer is drawn as.
     *
     * @param array $row
     * @return string[]
     */
    private static function nodeKeysOf(array $row)
    {
        $target = $row['_target'];
        $keys = [];
        $node = $target['edit']['node'] ?? null;
        if (is_string($node) && preg_match('/^(Value|ModuleAnswer|StandaloneObject):[0-9a-f-]{36,64}$/i', $node)) {
            list($type, $address) = explode(':', $node, 2);
            $keys[] = $type . ':' . strtolower($address);
        }
        if ($target['element_type'] === 'AttributeValue') {
            $keys[] = 'Value:' . $target['address'];
        } else {
            $keys[] = AnalystGraphDocumentTool::STANDALONE . ':' . $target['address'];
            $keys[] = AnalystGraphDocumentTool::ANSWER . ':' . $target['address'];
        }
        return array_values(array_unique($keys));
    }

    /**
     * The collection's elements for these keys, kept on their rows.
     *
     * @param int $collectionId
     * @param array $wanted key => row index
     * @param array $rows
     * @return array key => element row
     */
    private function members($collectionId, array $wanted, array &$rows)
    {
        $byColumn = [];
        foreach ($wanted as $key => $at) {
            $target = $rows[$at]['_target'];
            $byColumn[$target['column']][$target['address']] = $key;
        }
        $members = [];
        foreach ($byColumn as $column => $keys) {
            $found = $this->model('CollectionElement')->find('all', [
                'recursive' => -1,
                'fields' => [
                    'CollectionElement.id', 'CollectionElement.element_type', 'CollectionElement.element_uuid',
                    'CollectionElement.element_sha256', 'CollectionElement.element_value',
                    'CollectionElement.description', 'CollectionElement.origin',
                ],
                'conditions' => [
                    'CollectionElement.collection_id' => $collectionId,
                    'CollectionElement.' . $column => array_map('strval', array_keys($keys)),
                ],
            ]);
            foreach ($found as $element) {
                $element = $element['CollectionElement'];
                $key = $keys[strtolower((string)$element[$column])] ?? null;
                if ($key !== null) {
                    $members[$key] = $element;
                    $rows[$wanted[$key]]['_element'] = $element;
                }
            }
        }
        return $members;
    }

    /**
     * @param array $user
     * @param int $collectionId
     * @return int[] Event ids, in the order their first member joined
     */
    private function tiedEventIds(array $user, $collectionId)
    {
        $elements = $this->model('CollectionElement')->find('all', [
            'recursive' => -1,
            'fields' => ['CollectionElement.element_type', 'CollectionElement.element_uuid'],
            'conditions' => [
                'CollectionElement.collection_id' => $collectionId,
                'CollectionElement.element_type' => ['Event', 'Attribute', 'Object'],
            ],
            'order' => ['CollectionElement.id' => 'ASC'],
        ]);
        $order = [];
        $byType = [];
        foreach ($elements as $i => $element) {
            $element = $element['CollectionElement'];
            $uuid = strtolower((string)$element['element_uuid']);
            $byType[$element['element_type']][$uuid] = $i;
        }
        $eventOf = [];
        if (!empty($byType['Event'])) {
            $Event = $this->model('Event');
            $conditions = $Event->createEventConditions($user);
            $conditions['AND'][] = ['Event.uuid' => array_merge(array_keys($byType['Event']), array_map('strtoupper', array_keys($byType['Event'])))];
            foreach ($Event->find('all', ['recursive' => -1, 'conditions' => $conditions, 'fields' => ['Event.id', 'Event.uuid']]) as $row) {
                $eventOf[$byType['Event'][strtolower($row['Event']['uuid'])]] = (int)$row['Event']['id'];
            }
        }
        if (!empty($byType['Attribute'])) {
            $rows = $this->model('MispAttribute')->fetchAttributesSimple($user, [
                'conditions' => ['Attribute.uuid' => array_merge(array_keys($byType['Attribute']), array_map('strtoupper', array_keys($byType['Attribute']))), 'Attribute.deleted' => 0],
                'fields' => ['Attribute.uuid', 'Attribute.event_id'],
            ]);
            foreach ($rows as $row) {
                $eventOf[$byType['Attribute'][strtolower($row['Attribute']['uuid'])]] = (int)$row['Attribute']['event_id'];
            }
        }
        if (!empty($byType['Object'])) {
            $rows = $this->model('MispObject')->fetchObjectSimple($user, [
                'conditions' => ['Object.uuid' => array_merge(array_keys($byType['Object']), array_map('strtoupper', array_keys($byType['Object']))), 'Object.deleted' => 0],
                'fields' => ['Object.uuid', 'Object.event_id'],
            ]);
            foreach ($rows as $row) {
                $eventOf[$byType['Object'][strtolower($row['Object']['uuid'])]] = (int)$row['Object']['event_id'];
            }
        }
        ksort($eventOf);
        return array_values(array_unique($eventOf));
    }

    /**
     * `ACLComponent::canModifyEvent` as SQL.
     *
     * @param array $user
     * @return array|null Conditions, [] for any event, null for none
     */
    private function modifiableConditions(array $user)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return [];
        }
        $or = [];
        if (!empty($user['Role']['perm_modify_org'])) {
            $or[] = ['Event.orgc_id' => $user['org_id']];
        }
        if (!empty($user['Role']['perm_modify'])) {
            $or[] = ['Event.user_id' => $user['id']];
        }
        return empty($or) ? null : ['OR' => $or];
    }

    /**
     * @param array $user
     * @param array $modify
     * @param array $conditions
     * @param array|null $order
     * @param int $limit
     * @return array As the picker lists them
     */
    private function eventRows(array $user, array $modify, array $conditions, $order, $limit)
    {
        $Event = $this->model('Event');
        $where = $Event->createEventConditions($user);
        if (!empty($modify)) {
            $where['AND'][] = $modify;
        }
        if (!empty($conditions)) {
            $where['AND'][] = $conditions;
        }
        $rows = $Event->find('all', [
            'recursive' => -1,
            'conditions' => $where,
            'fields' => [
                'Event.id', 'Event.uuid', 'Event.info', 'Event.date', 'Event.distribution',
                'Event.sharing_group_id', 'Event.published', 'Event.attribute_count', 'Event.orgc_id',
            ],
            'contain' => ['Orgc' => ['fields' => ['Orgc.id', 'Orgc.uuid', 'Orgc.name']]],
            'order' => $order ?: [],
            'limit' => $limit,
        ]);
        $groups = $this->groupNames(array_map(function ($row) {
            return ['Event' => $row['Event']];
        }, $rows));
        $out = [];
        foreach ($rows as $row) {
            $event = $row['Event'];
            $out[] = [
                'id' => (int)$event['id'],
                'uuid' => $event['uuid'],
                'info' => $event['info'],
                'date' => $event['date'],
                'distribution' => (int)$event['distribution'],
                'sharing_group' => (int)$event['distribution'] === 4
                    ? ['id' => (int)$event['sharing_group_id'], 'name' => $groups[(int)$event['sharing_group_id']] ?? null]
                    : null,
                'published' => !empty($event['published']),
                'attribute_count' => (int)$event['attribute_count'],
                'Orgc' => $row['Orgc'] ?? null,
            ];
        }
        return $out;
    }

    /**
     * Value types to offer: the hint when it fits, what the freetext parser
     * reads, the common indicator types the value validates as, then text.
     *
     * @param string $value
     * @param mixed $hint
     * @return string[]
     */
    private function typesFor($value, $hint = null)
    {
        $definitions = $this->model('MispAttribute')->typeDefinitions;
        $candidates = is_string($hint) ? [$hint] : [];
        $candidates = array_merge($candidates, ValueTypeGuessTool::read($value, array_keys($definitions)));
        $common = ValueTypeGuessTool::rank($value, array_values(array_intersect(self::COMMON_TYPES, array_keys($definitions))));
        $candidates = array_merge($candidates, $common[ValueTypeGuessTool::FITS], ['text']);
        $types = [];
        foreach (array_unique($candidates) as $type) {
            if (isset($definitions[$type]) && strpos($type, '|') === false && ValueTypeGuessTool::accepts($type, $value)) {
                $types[] = $type;
            }
        }
        return $types;
    }

    /**
     * @param string $type
     * @return string[]
     */
    private function categoriesFor($type)
    {
        $Attribute = $this->model('MispAttribute');
        return ValueNewEventTool::categoriesFor($type, $Attribute->typeDefinitions, $Attribute->categoryDefinitions);
    }

    /**
     * @param string $type
     * @return bool
     */
    private function typeIds($type)
    {
        return !empty($this->model('MispAttribute')->typeDefinitions[$type]['to_ids']);
    }

    /**
     * @param array $rows
     * @return array type => {categories, to_ids}
     */
    private function typeInfo(array $rows)
    {
        $out = [];
        foreach ($rows as $row) {
            foreach ($row['types'] ?? [] as $type) {
                if (!isset($out[$type])) {
                    $out[$type] = ['categories' => $this->categoriesFor($type), 'to_ids' => $this->typeIds($type)];
                }
            }
        }
        return $out ?: new stdClass();
    }

    /**
     * The value rows whose value MISP holds only in events shared more
     * narrowly than the event, for this user.
     *
     * @param array $user
     * @param array $rows
     * @param array $target
     * @return string[] Row keys
     */
    private function narrower(array $user, array $rows, array $target)
    {
        $hexes = [];
        foreach ($rows as $row) {
            if ($row['becomes'] === 'attribute' && in_array($row['kind'], ['value', 'answer'], true)) {
                $hexes[$row['_target']['address']] = $row['key'];
            }
        }
        if (empty($hexes)) {
            return [];
        }
        $out = [];
        foreach ($this->model('CollectionElement')->narrowerValues($user, $this->levelOf($target)[0], array_keys($hexes)) as $hex) {
            $out[] = $hexes[$hex];
        }
        return $out;
    }

    /**
     * @param array $target
     * @return array [distribution, sharing_group_id]
     */
    private function levelOf(array $target)
    {
        if (isset($target['event'])) {
            return [(int)$target['event']['Event']['distribution'], $target['event']['Event']['sharing_group_id']];
        }
        $distribution = (int)($target['distribution'] ?? 0);
        return [$distribution, $distribution === 4 ? ($target['sharing_group_id'] ?? null) : null];
    }

    /**
     * @param array $target
     * @return array
     */
    private function targetSummary(array $target)
    {
        if (isset($target['event'])) {
            $event = $target['event']['Event'];
            return ['event' => [
                'id' => (int)$event['id'],
                'uuid' => $event['uuid'],
                'info' => $event['info'],
                'distribution' => (int)$event['distribution'],
                'sharing_group_id' => (int)$event['distribution'] === 4 ? (int)$event['sharing_group_id'] : null,
            ]];
        }
        $level = $this->levelOf($target);
        return ['distribution' => $level[0], 'sharing_group_id' => $level[1] === null ? null : (int)$level[1]];
    }

    /**
     * @param array $rows Rows with an Event and, for attributes, an Object
     * @return array sharing group id => name
     */
    private function groupNames(array $rows)
    {
        $ids = [];
        foreach ($rows as $row) {
            foreach (['Event', 'Object', 'Attribute'] as $part) {
                if (isset($row[$part]['distribution']) && (int)$row[$part]['distribution'] === 4 && !empty($row[$part]['sharing_group_id'])) {
                    $ids[(int)$row[$part]['sharing_group_id']] = true;
                }
            }
        }
        if (empty($ids)) {
            return [];
        }
        return ClassRegistry::init('SharingGroup')->find('list', [
            'recursive' => -1,
            'fields' => ['SharingGroup.id', 'SharingGroup.name'],
            'conditions' => ['SharingGroup.id' => array_keys($ids)],
        ]);
    }

    /**
     * How narrowly a record is shared: the narrowest of its event, its object
     * and itself, an inherited level deferring outward.
     *
     * @param array $row {Event, Object?, Attribute?}
     * @return array [distribution, sharing_group_id]
     */
    public static function reach(array $row)
    {
        $out = [(int)$row['Event']['distribution'], $row['Event']['sharing_group_id']];
        foreach (['Object', 'Attribute'] as $part) {
            if (empty($row[$part]['id']) && $part === 'Object') {
                continue;
            }
            if (!isset($row[$part]['distribution']) || (int)$row[$part]['distribution'] === 5) {
                continue;
            }
            $level = [(int)$row[$part]['distribution'], $row[$part]['sharing_group_id']];
            if (DistributionLevel::reachesFewer($level, $out)) {
                $out = $level;
            }
        }
        return $out;
    }

    /**
     * @param array $reach
     * @param array $groups
     * @return array {distribution, sharing_group}
     */
    private static function reachOut(array $reach, array $groups)
    {
        return [
            'distribution' => (int)$reach[0],
            'sharing_group' => (int)$reach[0] === 4
                ? ['id' => (int)$reach[1], 'name' => $groups[(int)$reach[1]] ?? null]
                : null,
        ];
    }

    /**
     * @param array $reach
     * @return array {distribution, sharing_group_id}
     */
    private static function capOf(array $reach)
    {
        return ['distribution' => (int)$reach[0], 'sharing_group_id' => (int)$reach[0] === 4 ? $reach[1] : null];
    }

    /**
     * @param string $name
     * @param array|null $template
     * @param string $metaCategory
     * @param string $comment
     * @param array $attributes
     * @return array
     */
    private static function objectFields($name, $template, $metaCategory, $comment, array $attributes)
    {
        return [
            'name' => $name,
            'template' => $template === null ? null : [
                'uuid' => strtolower($template['ObjectTemplate']['uuid']),
                'version' => (int)$template['ObjectTemplate']['version'],
                'name' => $template['ObjectTemplate']['name'],
            ],
            'meta_category' => $template['ObjectTemplate']['meta-category'] ?? (string)$metaCategory,
            'comment' => (string)$comment,
            'attributes' => array_values($attributes),
        ];
    }

    /**
     * A member MISP did not hold gives way; an answer joins.
     *
     * @param array $row
     * @param array|null $member
     * @param array $target
     * @return array
     */
    private static function placed(array $row, $member, array $target)
    {
        $row['member'] = $member !== null;
        if ($row['becomes'] !== null) {
            $row[$member !== null ? 'gives_way' : 'joins'] = true;
        }
        $origin = $member !== null ? CollectionElement::decodedOrigin($member['origin'] ?? null) : ($target['origin'] ?? null);
        if ($origin !== null) {
            $row['origin'] = $origin;
        }
        if ($member !== null && (string)($member['description'] ?? '') !== '') {
            $row['why'] = $member['description'];
        }
        return $row;
    }

    /**
     * @param string|null $key
     * @param string|null $kind
     * @param string|null $becomes
     * @param string|null $reason
     * @return array
     */
    private static function row($key, $kind, $becomes, $reason = null)
    {
        $row = ['key' => $key, 'kind' => $kind, 'becomes' => $becomes];
        if ($reason !== null) {
            $row['reason'] = $reason;
        }
        return $row;
    }

    /**
     * @param array $row
     * @return array Without the fields that start with _
     */
    private function publicRow(array $row)
    {
        foreach (array_keys($row) as $field) {
            if ($field[0] === '_') {
                unset($row[$field]);
            }
        }
        if (isset($row['attributes'])) {
            foreach ($row['attributes'] as $i => $attribute) {
                unset($row['attributes'][$i]['_reach']);
            }
        }
        return $row;
    }

    /**
     * @param array $rows
     * @return array
     */
    private static function counts(array $rows)
    {
        $out = ['attribute' => 0, 'object' => 0, 'tag' => 0, 'link' => 0, 'left_out' => 0, 'gives_way' => 0, 'joins' => 0, 'capped' => 0];
        foreach ($rows as $row) {
            if ($row['becomes'] === null) {
                $out['left_out']++;
                continue;
            }
            $out[$row['becomes']]++;
            foreach (['gives_way', 'joins', 'capped'] as $flag) {
                if (!empty($row[$flag])) {
                    $out[$flag]++;
                }
            }
        }
        return $out;
    }

    /**
     * @param array $rows
     * @return array
     */
    private static function states(array $rows)
    {
        $out = ['saved' => 0, 'existing' => 0, 'failed' => 0, 'skipped' => 0, 'replaced' => 0];
        foreach ($rows as $row) {
            $out[$row['state']]++;
            if (!empty($row['replaced'])) {
                $out['replaced']++;
            }
        }
        return $out;
    }
}
