<?php
App::uses('PivotSeed', 'Tools/PivotExplorer');
App::uses('JSONConverterTool', 'Tools');
App::uses('RedisTool', 'Tools');

/**
 * The Pivot Explorer's view of one event: the elements it opens on, a search
 * over the rest, and the elements a feed or server has seen. Elements leave
 * through Event::fetchEvent(), so each carries exactly what /events/view
 * gives the same user.
 */
class PivotGraphTool
{
    const PAGE = 5000;

    // Analyst relationship targets the canvas draws.
    const DRAWN_TARGETS = ['Attribute', 'Object', 'Event', 'GalaxyCluster'];

    // A feed-hit scan is kept this long for the count and fetch that follow it.
    const HIT_TTL = 300;

    // Attributes in no object. A range, so the planner measures it: object_id
    // 0 is most of the table, which its index statistics do not show.
    const FREE = ['Attribute.object_id <' => 1];

    /** @var Event */
    private $Event;

    public function __construct(Event $Event)
    {
        $this->Event = $Event;
    }

    /**
     * What the canvas opens on.
     *
     * @param array $user
     * @param array $event Event.id, uuid, timestamp, attribute_count
     * @return array the event as /events/view shapes it, and `meta`
     */
    public function seed(array $user, array $event)
    {
        $eventId = (int)$event['id'];
        $seed = new PivotSeed();
        $this->linkReferences($user, $eventId, $seed);
        $this->linkRelationships($user, $event, $seed);

        // Too much linked to draw: say what, rather than load it.
        if ($seed->linksFit()) {
            $this->countChildren($user, $eventId, $seed);
        }
        if (!$seed->linksFit()) {
            $payload = $this->fetch($user, $eventId, [], []);
            $payload['meta'] = [
                'feed_hits' => 'pivot',
                'linked' => $seed->linkedSummary(),
                'budget' => PivotSeed::NODE_BUDGET,
                'feed_scan_limit' => PivotSeed::FEED_SCAN_LIMIT,
            ];
            return $payload;
        }

        if (!PivotSeed::scansFeedHits($event['attribute_count'])) {
            $feedHits = 'pivot';
        } else {
            $feedHits = $this->seedFeedHits($user, $eventId, $seed);
        }
        $elements = $seed->elements();
        $payload = $this->fetch($user, $eventId, $elements['attributes'], $elements['objects']);
        $payload['meta'] = [
            'feed_hits' => $feedHits,
            'budget' => PivotSeed::NODE_BUDGET,
            'feed_scan_limit' => PivotSeed::FEED_SCAN_LIMIT,
        ];
        return $payload;
    }

    /**
     * The event's attributes and objects not on the canvas, matching the
     * search. An object stands for any of its attributes that matches. One
     * read, grouped by kind and category, gives the total under every other
     * narrowing and each facet's counts.
     *
     * @param array $user
     * @param int $eventId
     * @param array $options q, kinds (attribute|object), category, exclude (uuids)
     * @return array 'total' under every narrowing; 'kinds' and 'by_category'
     *               under the search alone
     */
    public function countElements(array $user, $eventId, array $options)
    {
        $groups = trim((string)($options['q'] ?? '')) === ''
            ? $this->elementGroups($user, $eventId, $options['exclude'] ?? [])
            : $this->matchingGroups($user, $eventId, $options);
        $kinds = $options['kinds'] ?? ['attribute', 'object'];
        $chosen = (string)($options['category'] ?? '');
        $out = ['total' => 0, 'kinds' => ['attribute' => 0, 'object' => 0], 'by_category' => []];
        foreach ($groups as [$name, $free, $objects]) {
            $out['kinds']['attribute'] += $free;
            $out['kinds']['object'] += $objects;
            $out['by_category'][$name] = ($out['by_category'][$name] ?? 0) + $free + $objects;
            if ($chosen === '' || $chosen === $name) {
                $out['total'] += (in_array('attribute', $kinds, true) ? $free : 0)
                    + (in_array('object', $kinds, true) ? $objects : 0);
            }
        }
        return $out;
    }

    /**
     * Free attributes by category and objects by meta-category, read from
     * their own tables when nothing is searched for.
     *
     * @return array [category, free attributes, objects]
     */
    private function elementGroups(array $user, $eventId, array $exclude)
    {
        // Counted here rather than grouped in SQL: on an event that is much of
        // the table, the planner walks the category index over all of it.
        $free = [];
        $last = 0;
        do {
            $rows = $this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.id', 'Attribute.category'],
                'conditions' => array_merge(self::FREE, ['Attribute.id >' => $last], $this->excluding('Attribute', $exclude)),
                'order' => ['Attribute.id'],
                'limit' => self::PAGE,
            ]);
            foreach ($rows as $row) {
                $category = $row['Attribute']['category'];
                $free[$category] = ($free[$category] ?? 0) + 1;
                $last = $row['Attribute']['id'];
            }
        } while (count($rows) === self::PAGE);
        $groups = [];
        foreach ($free as $category => $n) {
            $groups[] = [$category, $n, 0];
        }
        $objects = $this->elementFind($user, $eventId, 'Object', [
            'fields' => ['Object.meta-category', 'COUNT(*) AS n'],
            'conditions' => $this->excluding('Object', $exclude),
            'group' => ['Object.meta-category'],
        ]);
        foreach ($objects as $row) {
            $groups[] = [$row['Object']['meta-category'] ?: 'object', 0, (int)$row[0]['n']];
        }
        return $groups;
    }

    /**
     * As elementGroups(), for a search: every attribute is read and an object
     * counts once for any of its attributes that matches.
     */
    private function matchingGroups(array $user, $eventId, array $options)
    {
        $free = [];
        $objects = [];
        $last = 0;
        do {
            $rows = $this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.id', 'Attribute.object_id', 'Attribute.category', 'Object.meta-category'],
                'conditions' => array_merge(
                    $this->elementConditions(['q' => $options['q'], 'exclude' => $options['exclude'] ?? []]),
                    [['Attribute.id >' => $last]]
                ),
                'order' => ['Attribute.id'],
                'limit' => self::PAGE,
            ]);
            foreach ($rows as $row) {
                $objectId = (int)$row['Attribute']['object_id'];
                if ($objectId) {
                    $objects[$objectId] = $row['Object']['meta-category'] ?: 'object';
                } else {
                    $category = $row['Attribute']['category'];
                    $free[$category] = ($free[$category] ?? 0) + 1;
                }
                $last = $row['Attribute']['id'];
            }
        } while (count($rows) === self::PAGE);
        $groups = [];
        foreach ($free as $category => $n) {
            $groups[] = [$category, $n, 0];
        }
        foreach (array_count_values($objects) as $category => $n) {
            $groups[] = [$category, 0, $n];
        }
        return $groups;
    }

    private function excluding($alias, array $uuids)
    {
        return empty($uuids) ? [] : ["$alias.uuid !=" => $uuids];
    }

    /**
     * @param array $user
     * @param int $eventId
     * @param array $options as for countElements()
     * @return array|null as seed() returns it, without `meta`; null above the budget
     */
    public function fetchElements(array $user, $eventId, array $options)
    {
        if (trim((string)($options['q'] ?? '')) === '') {
            return $this->fetchUnsearched($user, $eventId, $options);
        }
        $attributes = [];
        $objects = [];
        $last = 0;
        do {
            $rows = $this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.id', 'Attribute.object_id'],
                'conditions' => array_merge($this->elementConditions($options), [['Attribute.id >' => $last]]),
                'order' => ['Attribute.id'],
                'limit' => self::PAGE,
            ]);
            foreach ($rows as $row) {
                if ((int)$row['Attribute']['object_id']) {
                    $objects[(int)$row['Attribute']['object_id']] = true;
                } else {
                    $attributes[(int)$row['Attribute']['id']] = true;
                }
                $last = $row['Attribute']['id'];
            }
            if (count($attributes) + count($objects) > PivotSeed::NODE_BUDGET) {
                return null;
            }
        } while (count($rows) === self::PAGE);
        return $this->fetch($user, $eventId, array_keys($attributes), array_keys($objects));
    }

    /**
     * As fetchElements(), when nothing is searched for: free attributes and
     * objects read from their own tables, as elementGroups() counts them.
     */
    private function fetchUnsearched(array $user, $eventId, array $options)
    {
        $kinds = $options['kinds'] ?? ['attribute', 'object'];
        $category = (string)($options['category'] ?? '');
        $exclude = $options['exclude'] ?? [];
        $attributes = [];
        $objects = [];
        if (in_array('attribute', $kinds, true)) {
            $conditions = array_merge(self::FREE, $this->excluding('Attribute', $exclude));
            if ($category !== '') {
                $conditions['Attribute.category'] = $category;
            }
            $attributes = array_column(array_column($this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.id'],
                'conditions' => $conditions,
                'limit' => PivotSeed::NODE_BUDGET + 1,
            ]), 'Attribute'), 'id');
        }
        if (in_array('object', $kinds, true)) {
            $conditions = $this->excluding('Object', $exclude);
            if ($category !== '') {
                $conditions['Object.meta-category'] = $category;
            }
            $objects = array_column(array_column($this->elementFind($user, $eventId, 'Object', [
                'fields' => ['Object.id'],
                'conditions' => $conditions,
                'limit' => PivotSeed::NODE_BUDGET + 1,
            ]), 'Object'), 'id');
        }
        if (count($attributes) + count($objects) > PivotSeed::NODE_BUDGET) {
            return null;
        }
        return $this->fetch($user, $eventId, $attributes, $objects);
    }

    /**
     * The tags and galaxy clusters on the event and on its attributes the
     * user may see, as one record carrying them: `Tag` and `Galaxy`.
     *
     * @param array $user
     * @param int $eventId
     * @return array
     */
    public function labels(array $user, $eventId)
    {
        $tagIds = [];
        $eventTags = $this->Event->EventTag->find('all', [
            'conditions' => ['EventTag.event_id' => $eventId],
            'fields' => ['EventTag.tag_id', 'EventTag.local', 'EventTag.relationship_type'],
            'recursive' => -1,
        ]);
        foreach ($eventTags as $row) {
            $tagIds[$row['EventTag']['tag_id']] = $tagIds[$row['EventTag']['tag_id']] ?? $row['EventTag'];
        }
        $attributeTags = $this->attributeFind($user, $eventId, [
            'fields' => ['AttributeTag.tag_id', 'MIN(AttributeTag.local) AS local'],
            'joins' => [[
                'table' => 'attribute_tags', 'alias' => 'AttributeTag', 'type' => 'INNER',
                'conditions' => ['AttributeTag.attribute_id = Attribute.id'],
            ]],
            'group' => ['AttributeTag.tag_id'],
        ]);
        foreach ($attributeTags as $row) {
            $tagId = $row['AttributeTag']['tag_id'];
            $tagIds[$tagId] = $tagIds[$tagId] ?? ['local' => $row[0]['local']];
        }
        if (empty($tagIds)) {
            return ['Tag' => [], 'Galaxy' => []];
        }
        // The view's REST payload carries exportable tags only.
        $tags = $this->Event->EventTag->Tag->find('all', [
            'conditions' => ['Tag.id' => array_map('strval', array_keys($tagIds)), 'Tag.exportable' => 1],
            'fields' => ['Tag.id', 'Tag.name', 'Tag.colour', 'Tag.is_galaxy', 'Tag.hide_tag'],
            'recursive' => -1,
        ]);
        $out = ['Tag' => [], 'Galaxy' => []];
        $galaxyTags = [];
        foreach ($tags as $row) {
            $tag = $row['Tag'];
            $use = $tagIds[$tag['id']];
            $out['Tag'][] = $tag + [
                'local' => !empty($use['local']),
                'relationship_type' => $use['relationship_type'] ?? null,
            ];
            if ($tag['is_galaxy']) {
                $galaxyTags[$tag['id']] = $tag['name'];
            }
        }
        if (!empty($galaxyTags)) {
            $clusters = ClassRegistry::init('GalaxyCluster')->getClustersByTags($galaxyTags, $user, true, false);
            $galaxies = [];
            foreach ($clusters as $row) {
                $cluster = $row['GalaxyCluster'];
                $galaxy = $cluster['Galaxy'];
                unset($cluster['Galaxy']);
                if (!isset($galaxies[$galaxy['id']])) {
                    $galaxies[$galaxy['id']] = $galaxy + ['GalaxyCluster' => []];
                }
                $galaxies[$galaxy['id']]['GalaxyCluster'][] = $cluster;
            }
            $out['Galaxy'] = array_values($galaxies);
        }
        return $out;
    }

    /**
     * The attributes of the event a feed or server has seen, read once per
     * event version and kept briefly for the user who asked.
     *
     * @param array $user
     * @param array $event Event.id, timestamp
     * @param array $options q, exclude (uuids)
     * @return array 'rows': [attribute id, object id, uuid, object uuid,
     *               value, source keys ('feed:<id>', 'server:<id>')],
     *               'sources': key => name
     */
    public function feedHits(array $user, array $event, array $options)
    {
        $scan = $this->cachedFeedScan($user, $event);
        $exclude = array_flip($options['exclude'] ?? []);
        $q = mb_strtolower((string)($options['q'] ?? ''));
        $rows = [];
        foreach ($scan['rows'] as $row) {
            if (isset($exclude[$row[2]]) || ($row[3] !== '' && isset($exclude[$row[3]]))) {
                continue;
            }
            if ($q !== '' && strpos(mb_strtolower($row[4]), $q) === false) {
                continue;
            }
            $rows[] = $row;
        }
        return ['rows' => $rows, 'sources' => $scan['sources']];
    }

    /**
     * @param array $rows as feedHits() returns them
     * @param string $source a source key, or '' for all
     * @return array
     */
    public static function fromSource(array $rows, $source)
    {
        if ($source === '') {
            return $rows;
        }
        return array_values(array_filter($rows, function ($row) use ($source) {
            return in_array($source, $row[5], true);
        }));
    }

    /**
     * @param array $rows as feedHits() returns them
     * @param string $source as for fromSource()
     * @return array 'total' landing units from $source, 'by_source' key => units
     */
    public static function countHits(array $rows, $source = '')
    {
        $units = [];
        $bySource = [];
        foreach ($rows as $row) {
            $unit = $row[1] ? 'o' . $row[1] : 'a' . $row[0];
            if ($source === '' || in_array($source, $row[5], true)) {
                $units[$unit] = true;
            }
            foreach ($row[5] as $key) {
                $bySource[$key][$unit] = true;
            }
        }
        return [
            'total' => count($units),
            'by_source' => array_map('count', $bySource),
        ];
    }

    /**
     * @param array $user
     * @param int $eventId
     * @param array $rows as feedHits() returns them
     * @return array|null as fetchElements()
     */
    public function fetchHits(array $user, $eventId, array $rows)
    {
        $attributes = [];
        $objects = [];
        foreach ($rows as $row) {
            if ($row[1]) {
                $objects[$row[1]] = true;
            } else {
                $attributes[$row[0]] = true;
            }
        }
        if (count($attributes) + count($objects) > PivotSeed::NODE_BUDGET) {
            return null;
        }
        return $this->fetch($user, $eventId, array_keys($attributes), array_keys($objects));
    }

    /**
     * @param array $user
     * @param int $eventId
     * @param array $attributeIds
     * @param array $objectIds
     * @return array the event as /events/view shapes it
     */
    public function fetch(array $user, $eventId, array $attributeIds, array $objectIds)
    {
        $events = $this->Event->fetchEvent($user, [
            'eventid' => $eventId,
            'elementIds' => ['attributes' => $attributeIds, 'objects' => $objectIds],
            'includeAnalystData' => true,
            'includeAttachments' => false,
            'deleted' => 0,
            'excludeLocalTags' => false,
            'includeWarninglistHits' => true,
            'includeFeedCorrelations' => 1,
            'includeServerCorrelations' => 1,
            'includeEventCorrelations' => false,
            'noSightings' => true,
        ]);
        if (empty($events)) {
            throw new NotFoundException(__('Invalid event'));
        }
        return JSONConverterTool::convert($events[0], false, true);
    }

    private function linkReferences(array $user, $eventId, PivotSeed $seed)
    {
        $refs = ClassRegistry::init('ObjectReference')->find('all', [
            'conditions' => ['ObjectReference.event_id' => $eventId, 'ObjectReference.deleted' => 0],
            'fields' => ['ObjectReference.object_id', 'ObjectReference.referenced_uuid', 'ObjectReference.referenced_type',
                         'ObjectReference.relationship_type'],
            'recursive' => -1,
            'callbacks' => false,
        ]);
        if (empty($refs)) {
            return;
        }
        $sourceIds = [];
        $objectUuids = [];
        $attributeUuids = [];
        foreach ($refs as $ref) {
            $ref = $ref['ObjectReference'];
            $sourceIds[$ref['object_id']] = true;
            if ((int)$ref['referenced_type'] === 1) {
                $objectUuids[$ref['referenced_uuid']] = true;
            } else {
                $attributeUuids[$ref['referenced_uuid']] = true;
            }
        }
        $sources = $this->visibleObjects($user, $eventId, 'Object.id', array_keys($sourceIds));
        $objects = $this->visibleObjects($user, $eventId, 'Object.uuid', array_keys($objectUuids));
        $attributes = $this->visibleAttributes($user, $eventId, array_keys($attributeUuids));
        $sourceIdSet = array_flip(array_column($sources, 'id'));
        foreach ($refs as $ref) {
            $ref = $ref['ObjectReference'];
            if (!isset($sourceIdSet[$ref['object_id']])) {
                continue;
            }
            if ((int)$ref['referenced_type'] === 1) {
                if (!isset($objects[$ref['referenced_uuid']])) {
                    continue;
                }
                $seed->linkObject($objects[$ref['referenced_uuid']]['id']);
            } else {
                if (!isset($attributes[$ref['referenced_uuid']])) {
                    continue;
                }
                $target = $attributes[$ref['referenced_uuid']];
                $seed->linkAttribute($target['id'], $target['object_id']);
            }
            $seed->linkObject($ref['object_id']);
            $seed->countReference($ref['relationship_type']);
        }
    }

    /**
     * Analyst relationships from or to the event and its elements. The far
     * end of one leaving the event cannot be checked without loading it, so
     * it is counted against the budget and left for the client to draw or not.
     */
    private function linkRelationships(array $user, array $event, PivotSeed $seed)
    {
        $Relationship = ClassRegistry::init('Relationship');
        $acl = $Relationship->buildConditions($user);
        $eventUuid = $event['uuid'];
        // [this end: [type, id, object id] | null for the event, far type, far uuid, uuid, type]
        $ends = [];

        foreach (['object_uuid' => 'related_object', 'related_object_uuid' => 'object'] as $near => $far) {
            $rows = $Relationship->find('all', [
                'conditions' => [$acl, "Relationship.$near" => $eventUuid],
                'fields' => ["Relationship.{$far}_type", "Relationship.{$far}_uuid", 'Relationship.uuid', 'Relationship.relationship_type'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
            foreach ($rows as $row) {
                $rel = $row['Relationship'];
                $ends[] = [null, $rel["{$far}_type"], $rel["{$far}_uuid"], $rel['uuid'], $rel['relationship_type']];
            }
            foreach (['Attribute', 'Object'] as $alias) {
                $fields = $alias === 'Attribute' ? ['Attribute.id', 'Attribute.object_id'] : ['Object.id'];
                $rows = $this->elementFind($user, $event['id'], $alias, [
                    'fields' => array_merge($fields, ["Relationship.{$far}_type", "Relationship.{$far}_uuid",
                                                      'Relationship.uuid', 'Relationship.relationship_type']),
                    'joins' => [[
                        'table' => 'relationships', 'alias' => 'Relationship', 'type' => 'INNER',
                        'conditions' => ["Relationship.$near = $alias.uuid"],
                    ]],
                    'conditions' => [$acl],
                ]);
                foreach ($rows as $row) {
                    $objectId = $alias === 'Attribute' ? (int)$row['Attribute']['object_id'] : 0;
                    $rel = $row['Relationship'];
                    $ends[] = [[$alias, (int)$row[$alias]['id'], $objectId],
                               $rel["{$far}_type"], $rel["{$far}_uuid"], $rel['uuid'], $rel['relationship_type']];
                }
            }
        }
        if (empty($ends)) {
            return;
        }

        // A far end in this event is linked like the near one, if the user sees it.
        $farAttributes = [];
        $farObjects = [];
        foreach ($ends as $end) {
            if ($end[1] === 'Attribute') {
                $farAttributes[$end[2]] = true;
            } elseif ($end[1] === 'Object') {
                $farObjects[$end[2]] = true;
            }
        }
        $ownAttributes = $this->visibleAttributes($user, $event['id'], array_keys($farAttributes));
        $ownObjects = $this->visibleObjects($user, $event['id'], 'Object.uuid', array_keys($farObjects));

        // Between two of the event's own elements, one is read from each end.
        $counted = [];
        foreach ($ends as [$near, $farType, $farUuid, $uuid, $type]) {
            if (!in_array($farType, self::DRAWN_TARGETS, true)) {
                continue;
            }
            if (!isset($counted[$uuid])) {
                $counted[$uuid] = true;
                $seed->countRelationship($type);
            }
            if ($near === null) {
                $seed->linkFarEnd('event:' . $eventUuid);
            } elseif ($near[0] === 'Attribute') {
                $seed->linkAttribute($near[1], $near[2]);
            } else {
                $seed->linkObject($near[1]);
            }
            if ($farType === 'Attribute' && isset($ownAttributes[$farUuid])) {
                $seed->linkAttribute($ownAttributes[$farUuid]['id'], $ownAttributes[$farUuid]['object_id']);
            } elseif ($farType === 'Object' && isset($ownObjects[$farUuid])) {
                $seed->linkObject($ownObjects[$farUuid]['id']);
            } elseif ($farType === 'Event' && $farUuid === $eventUuid) {
                $seed->linkFarEnd('event:' . $eventUuid);
            } else {
                $seed->linkFarEnd($farType . ':' . $farUuid);
                if ($farType === 'Attribute' || $farType === 'Object') {
                    // Another event's element lands beside its event's card.
                    $seed->linkFarEnd('card:' . $farType . ':' . $farUuid);
                }
            }
        }
    }

    private function countChildren(array $user, $eventId, PivotSeed $seed)
    {
        $objectIds = $seed->uncountedObjectIds();
        if (empty($objectIds)) {
            return;
        }
        $counts = array_fill_keys($objectIds, 0);
        foreach (array_chunk($objectIds, self::PAGE) as $chunk) {
            $rows = $this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.object_id', 'COUNT(*) AS n'],
                'conditions' => ['Attribute.object_id' => $chunk],
                'group' => ['Attribute.object_id'],
            ]);
            foreach ($rows as $row) {
                $counts[(int)$row['Attribute']['object_id']] = (int)$row[0]['n'];
            }
        }
        $seed->addChildCounts($counts);
    }

    /**
     * Offers each attribute a feed or server has seen to the seed, page by
     * page, and stops as soon as they cannot all fit.
     *
     * @return string 'seeded', 'over_budget' or 'none'
     */
    private function seedFeedHits(array $user, $eventId, PivotSeed $seed)
    {
        $scopes = $this->feedScopes($user);
        if (empty($scopes)) {
            return 'none';
        }
        $done = $this->scanPages($user, $eventId, $scopes, function (array $hits) use ($user, $eventId, $seed) {
            foreach ($hits as $hit) {
                $seed->hit($hit['id'], $hit['object_id']);
            }
            $this->countChildren($user, $eventId, $seed);
            return $seed->hitsFit();
        });
        if (!$done) {
            return 'over_budget';
        }
        return $seed->hasHits() ? 'seeded' : 'none';
    }

    private function cachedFeedScan(array $user, array $event)
    {
        $scan = ['rows' => [], 'sources' => []];
        $scopes = $this->feedScopes($user);
        if (empty($scopes)) {
            return $scan;
        }
        // Whatever decides what the user sees is part of the key, so a role
        // change is honoured at once.
        $key = 'misp:pivot_feed_hits:' . implode(':', [
            (int)$event['id'], (int)$event['timestamp'], (int)$user['id'], (int)$user['org_id'],
            empty($user['Role']['perm_site_admin']) ? 0 : 1, implode(',', $scopes),
        ]);
        try {
            $redis = RedisTool::init();
            $cached = $redis->get($key);
            if ($cached !== false) {
                return RedisTool::deserialize(RedisTool::decompress($cached));
            }
        } catch (Exception $e) {
            $redis = null;
        }
        $this->scanPages($user, $event['id'], $scopes, function (array $hits, array $sources) use (&$scan) {
            foreach ($hits as $hit) {
                $scan['rows'][] = [(int)$hit['id'], (int)$hit['object_id'], $hit['uuid'], $hit['object_uuid'], $hit['value'], $hit['sources']];
            }
            $scan['sources'] += $sources;
            return true;
        });
        if ($redis) {
            $redis->setex($key, self::HIT_TTL, RedisTool::compress(RedisTool::serialize($scan)));
        }
        return $scan;
    }

    /**
     * Reads the event's attributes the user may see by id, a page at a time,
     * and hands each page's feed and server hits to $onPage, which returns
     * false to stop.
     *
     * @return bool whether every page was read
     */
    private function scanPages(array $user, $eventId, array $scopes, callable $onPage)
    {
        $Feed = ClassRegistry::init('Feed');
        $last = 0;
        do {
            $rows = $this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.id', 'Attribute.uuid', 'Attribute.object_id', 'Object.uuid',
                             'Attribute.type', 'Attribute.value1_id', 'Attribute.value2_id', 'Attribute.disable_correlation'],
                'conditions' => ['Attribute.id >' => $last],
                'order' => ['Attribute.id'],
                'limit' => self::PAGE,
            ]);
            if (empty($rows)) {
                return true;
            }
            // Callbacks are off, so the value text is attached here
            ClassRegistry::init('AttributeValue')->attachValues($rows, 'Attribute');
            $attributes = [];
            foreach ($rows as $row) {
                $attribute = $row['Attribute'];
                $attribute['object_uuid'] = $row['Object']['uuid'] ?? '';
                $attribute['value'] = $attribute['value2'] === '' ? $attribute['value1'] : $attribute['value1'] . '|' . $attribute['value2'];
                $attributes[] = $attribute;
            }
            $last = end($rows)['Attribute']['id'];
            unset($rows);
            $sources = [];
            foreach ($scopes as $scope) {
                $found = [];
                $attributes = $Feed->attachFeedCorrelations($attributes, $user, $found, false, $scope);
                foreach ($found[$scope] ?? [] as $source) {
                    $sources[strtolower($scope) . ':' . $source['id']] = $source['name'];
                }
            }
            $hits = [];
            foreach ($attributes as $attribute) {
                $keys = [];
                foreach ($scopes as $scope) {
                    foreach ($attribute[$scope] ?? [] as $source) {
                        $keys[] = strtolower($scope) . ':' . $source['id'];
                    }
                }
                if (!empty($keys)) {
                    $hits[] = $attribute + ['sources' => $keys];
                }
            }
            if (!empty($hits) && !$onPage($hits, $sources)) {
                return false;
            }
        } while (count($attributes) === self::PAGE);
        return true;
    }

    /**
     * Feeds and servers the user may see hits from, as Event::fetchEvent()
     * decides it for the view.
     */
    private function feedScopes(array $user)
    {
        if (empty($user['Role']['perm_view_feed_correlations'])) {
            return [];
        }
        $scopes = ['Feed'];
        if (
            !empty($user['Role']['perm_site_admin']) ||
            $user['org_id'] == Configure::read('MISP.host_org_id') ||
            Configure::read('MISP.show_server_correlations_for_all_users', false)
        ) {
            $scopes[] = 'Server';
        }
        return $scopes;
    }

    /**
     * Narrowing for the element search, leaving out one facet's own filter
     * for its counts.
     */
    private function elementConditions(array $options, $skip = null)
    {
        $conditions = [];
        $kinds = $options['kinds'] ?? ['attribute', 'object'];
        if (!in_array('attribute', $kinds, true)) {
            $conditions[] = ['Attribute.object_id !=' => 0];
        }
        if (!in_array('object', $kinds, true)) {
            $conditions[] = self::FREE;
        }
        $q = trim((string)($options['q'] ?? ''));
        if ($q !== '') {
            $like = '%' . addcslashes($q, '%_\\') . '%';
            // value1 and value2 are case-insensitive, the rest is not.
            $lower = mb_strtolower($like);
            $conditions[] = ['OR' => [
                'Attribute.value1 LIKE' => $like,
                'Attribute.value2 LIKE' => $like,
                'LOWER(Attribute.type) LIKE' => $lower,
                'LOWER(Attribute.comment) LIKE' => $lower,
                'LOWER(Attribute.object_relation) LIKE' => $lower,
                'LOWER(Object.name) LIKE' => $lower,
                'LOWER(Object.comment) LIKE' => $lower,
            ]];
        }
        $category = (string)($options['category'] ?? '');
        if ($category !== '' && $skip !== 'category') {
            $conditions[] = ['OR' => [
                ['Attribute.object_id' => 0, 'Attribute.category' => $category],
                ['Attribute.object_id !=' => 0, 'Object.meta-category' => $category],
            ]];
        }
        if (!empty($options['exclude'])) {
            $conditions[] = ['Attribute.uuid !=' => $options['exclude']];
            $conditions[] = ['OR' => ['Attribute.object_id' => 0, 'Object.uuid !=' => $options['exclude']]];
        }
        return $conditions;
    }

    /**
     * Live attributes of the event the user may see, keyed by uuid.
     */
    private function visibleAttributes(array $user, $eventId, array $uuids)
    {
        $out = [];
        foreach (array_chunk($uuids, self::PAGE) as $chunk) {
            $rows = $this->attributeFind($user, $eventId, [
                'fields' => ['Attribute.id', 'Attribute.uuid', 'Attribute.object_id'],
                'conditions' => ['Attribute.uuid' => $chunk],
            ]);
            foreach ($rows as $row) {
                $out[$row['Attribute']['uuid']] = [
                    'id' => (int)$row['Attribute']['id'],
                    'object_id' => (int)$row['Attribute']['object_id'],
                ];
            }
        }
        return $out;
    }

    /**
     * Live objects of the event the user may see, keyed by uuid.
     */
    private function visibleObjects(array $user, $eventId, $field, array $values)
    {
        $out = [];
        foreach (array_chunk($values, self::PAGE) as $chunk) {
            $rows = $this->elementFind($user, $eventId, 'Object', [
                'fields' => ['Object.id', 'Object.uuid'],
                'conditions' => [$field => array_map('strval', $chunk)],
            ]);
            foreach ($rows as $row) {
                $out[$row['Object']['uuid']] = ['id' => (int)$row['Object']['id']];
            }
        }
        return $out;
    }

    private function attributeFind(array $user, $eventId, array $params, $findType = 'all')
    {
        return $this->elementFind($user, $eventId, 'Attribute', $params, $findType);
    }

    /**
     * A find over the event's live attributes or objects the user may see,
     * with Event (and, for attributes, Object) joined for the ACL.
     */
    private function elementFind(array $user, $eventId, $model, array $params, $findType = 'all')
    {
        if ($model === 'Attribute') {
            $Model = $this->Event->Attribute;
            $conditions = $Model->buildConditions($user);
            $conditions['AND'][] = ['Attribute.event_id' => $eventId, 'Attribute.deleted' => 0];
            $conditions['AND'][] = ['OR' => ['Attribute.object_id' => 0, 'Object.deleted' => 0]];
            $joins = [
                ['table' => 'events', 'alias' => 'Event', 'type' => 'INNER', 'conditions' => ['Event.id = Attribute.event_id']],
                ['table' => 'objects', 'alias' => 'Object', 'type' => 'LEFT', 'conditions' => ['Object.id = Attribute.object_id']],
            ];
        } else {
            $Model = $this->Event->Object;
            $conditions = $Model->buildConditions($user);
            $conditions['AND'][] = ['Object.event_id' => $eventId, 'Object.deleted' => 0];
            $joins = [
                ['table' => 'events', 'alias' => 'Event', 'type' => 'INNER', 'conditions' => ['Event.id = Object.event_id']],
            ];
        }
        foreach ($params['conditions'] ?? [] as $key => $condition) {
            $conditions['AND'][] = is_int($key) ? $condition : [$key => $condition];
        }
        unset($params['conditions']);
        if ($model === 'Attribute') {
            // Callbacks are off: value conditions are rewritten here, bounded
            // by the event so a search's unanchored LIKE is checked per row
            $conditions = ClassRegistry::init('AttributeValue')
                ->rewriteConditions($conditions, 'Attribute', true);
        }
        return $Model->find($findType, [
            'conditions' => $conditions,
            'joins' => array_merge($joins, $params['joins'] ?? []),
            'recursive' => -1,
            'callbacks' => false,
        ] + $params + ['order' => false]);
    }
}
