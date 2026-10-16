<?php
App::uses('AppModel', 'Model');
App::uses('Value', 'Model');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

/**
 * A value's neighbourhood as the Pivot Explorer draws it: records shaped
 * as an event payload shapes them, so the explorer's node builders read
 * them unchanged.
 *
 * A *unit* is what one occurrence lands as: the object holding it, or the
 * attribute itself when it sits in no object.
 */
class ValueGraph extends AppModel
{
    public $useTable = false;

    /** Units the opening graph draws. */
    const SEED_BUDGET = 60;

    /** Units one pivot run may land. */
    const PIVOT_BUDGET = 200;

    /** Newest occurrence rows read to pick units from. */
    const READ_CAP = 2000;

    /** Near-match rows drawn per engine. */
    const NEAR_CAP = 12;

    /** Reference rows read around the drawn units. */
    const REFERENCE_CAP = 300;

    const NOT_IN_OBJECT = '';

    private $models = array();

    private function model($alias)
    {
        if (!isset($this->models[$alias])) {
            $this->models[$alias] = ClassRegistry::init($alias);
        }
        return $this->models[$alias];
    }

    /**
     * The opening graph for a value.
     *
     * @param array $user
     * @param string $value
     * @return array
     */
    public function seed(array $user, $value)
    {
        $valueModel = $this->model('Value');
        $types = $valueModel->typesFor($user, $value);
        $read = $this->readUnits($user, array($value), array(), array());
        $linked = $this->linkedUnits($user, $read);
        $units = $this->pick($read, $linked, self::SEED_BUDGET);
        $slice = $this->slice($user, $units, true);
        $counts = $this->count($user, array($value), array(), array());

        return array(
            'value' => array(
                'value' => $value,
                'b64' => ValueUrlTool::encode($value),
                'types' => array_values(array_map(function ($t) {
                    return is_array($t) ? $t['type'] : $t;
                }, Value::asTypes($types))),
            ),
            'near' => $this->near($user, $value),
        ) + $this->sources($user, $value, $types) + $slice + array(
            'meta' => array(
                'occurrences' => array(
                    'total' => $valueModel->occurrenceCountFor(
                        $user,
                        $value
                    ),
                    'units' => $counts['total'],
                    'seeded' => count($units),
                    'objects' => count($slice['Object']),
                    'attributes' => count($slice['Attribute']),
                    'events' => count((array)$slice['events']),
                ),
                'budget' => self::SEED_BUDGET,
                'order' => 'linked-then-newest',
                'facets' => array(
                    'template' => $counts['by_template'],
                    'org' => $counts['by_org'],
                    'year' => $counts['by_year'],
                ),
            ),
        );
    }

    /**
     * More of these values' occurrences than the canvas holds: counted
     * with `count`, landed without it.
     *
     * @param array $user
     * @param array $values
     * @param array $filters template, org, year (lists)
     * @param array $exclude object and attribute uuids already drawn
     * @param bool $count
     * @return array
     */
    public function occurrences(array $user, array $values,
        array $filters, array $exclude, $count
    ) {
        $values = array_values(array_unique(array_map('strval', $values)));
        if ($count) {
            return $this->count($user, $values, $filters, $exclude);
        }
        $read = $this->readUnits($user, $values, $filters, $exclude);
        $units = $this->pick($read, array(), self::PIVOT_BUDGET);
        return $this->slice($user, $units, false);
    }

    /**
     * The newest occurrences as units, each keyed `o<object id>` or
     * `a<attribute id>`, newest first. One statement per value, merged.
     */
    private function readUnits(array $user, array $values,
        array $filters, array $exclude
    ) {
        $attributes = $this->model('MispAttribute');
        $rows = array();
        foreach ($values as $value) {
            $conditions = $this->conditions($user, $value, $filters, $exclude);
            $found = $attributes->find('all', array(
                'conditions' => $conditions,
                'fields' => array(
                    'Attribute.id', 'Attribute.uuid', 'Attribute.event_id',
                    'Attribute.object_id', 'Attribute.timestamp',
                ),
                'contain' => array(
                    'Event' => array('fields' => array('Event.id')),
                    'Object' => array('fields' => array(
                        'Object.id', 'Object.uuid',
                    )),
                ),
                'order' => array('Attribute.timestamp DESC'),
                'limit' => self::READ_CAP,
            ));
            foreach ($found as $row) {
                $rows[] = $row;
            }
        }
        usort($rows, function ($a, $b) {
            return (int)$b['Attribute']['timestamp']
                - (int)$a['Attribute']['timestamp'];
        });

        $units = array();
        foreach ($rows as $row) {
            $a = $row['Attribute'];
            $inObject = !empty($a['object_id']) && !empty($row['Object']['uuid']);
            $key = $inObject ? 'o' . $a['object_id'] : 'a' . $a['id'];
            if (!isset($units[$key])) {
                $units[$key] = array(
                    'kind' => $inObject ? 'object' : 'attribute',
                    'id' => (int)($inObject ? $a['object_id'] : $a['id']),
                    'uuid' => $inObject ? $row['Object']['uuid'] : $a['uuid'],
                    'event_id' => (int)$a['event_id'],
                    'holds' => array(),
                );
            }
            $units[$key]['holds'][$a['id']] = $a['uuid'];
        }
        return $units;
    }

    private function conditions(array $user, $value, array $filters,
        array $exclude
    ) {
        $attributes = $this->model('MispAttribute');
        $conditions = $attributes->buildConditions($user);
        $conditions['AND'][] = $this->model('Value')->conditionsFor($value);
        $conditions['AND'][] = array('Attribute.deleted' => 0);
        $conditions['AND'][] = array('OR' => array(
            'Attribute.object_id' => 0,
            'Object.deleted' => 0,
        ));
        if (!empty($filters['template'])) {
            $names = array_map('strval', (array)$filters['template']);
            $inObject = array_values(array_diff($names, array(self::NOT_IN_OBJECT)));
            $branches = array();
            if (!empty($inObject)) {
                $branches[] = array('Object.name' => $inObject);
            }
            if (in_array(self::NOT_IN_OBJECT, $names, true)) {
                $branches[] = array('Attribute.object_id' => 0);
            }
            $conditions['AND'][] = count($branches) === 1
                ? $branches[0]
                : array('OR' => $branches);
        }
        if (!empty($filters['org'])) {
            $conditions['AND'][] = array(
                'Event.orgc_id' => array_map('intval', (array)$filters['org']),
            );
        }
        if (!empty($filters['year'])) {
            $years = array();
            foreach ((array)$filters['year'] as $year) {
                $year = (int)$year;
                $years[] = array('Attribute.timestamp BETWEEN ? AND ?' => array(
                    gmmktime(0, 0, 0, 1, 1, $year),
                    gmmktime(0, 0, 0, 1, 1, $year + 1) - 1,
                ));
            }
            $conditions['AND'][] = count($years) === 1
                ? $years[0]
                : array('OR' => $years);
        }
        $exclude = array_values(array_filter($exclude, 'is_string'));
        if (!empty($exclude)) {
            $conditions['AND'][] = array(
                'NOT' => array('Attribute.uuid' => $exclude),
            );
            $conditions['AND'][] = array('OR' => array(
                'Attribute.object_id' => 0,
                'NOT' => array('Object.uuid' => $exclude),
            ));
        }
        return $conditions;
    }

    /**
     * Units touched by a live object reference or analyst relationship
     * reaching outside the value's own set, keyed as readUnits() keys
     * them.
     */
    private function linkedUnits(array $user, array $units)
    {
        $objectIds = array();
        $attributeIds = array();
        $byUuid = array();
        foreach ($units as $key => $unit) {
            if ($unit['kind'] === 'object') {
                $objectIds[$unit['id']] = $key;
                $byUuid[$unit['uuid']] = $key;
            }
            foreach ($unit['holds'] as $id => $uuid) {
                $attributeIds[$id] = $key;
                $byUuid[$uuid] = $key;
            }
        }
        $linked = array();
        foreach ($this->referenceRows($user, $objectIds, $attributeIds) as $row) {
            if (isset($objectIds[$row['object_id']])) {
                $linked[$objectIds[$row['object_id']]] = true;
            }
            $target = (int)$row['referenced_type'] === 1
                ? $objectIds
                : $attributeIds;
            if (isset($target[$row['referenced_id']])) {
                $linked[$target[$row['referenced_id']]] = true;
            }
        }
        foreach ($this->relationshipUuids($user, array_keys($byUuid)) as $uuid) {
            if (isset($byUuid[$uuid])) {
                $linked[$byUuid[$uuid]] = true;
            }
        }
        return $linked;
    }

    /**
     * Live references with one end in these objects or attributes and the
     * other outside them, readable by the user. One statement per end.
     */
    private function referenceRows(array $user, array $objectIds,
        array $attributeIds
    ) {
        $reference = $this->model('ObjectReference');
        $fields = array(
            'ObjectReference.id', 'ObjectReference.uuid',
            'ObjectReference.object_id',
            'ObjectReference.referenced_id', 'ObjectReference.referenced_uuid',
            'ObjectReference.referenced_type',
            'ObjectReference.relationship_type',
        );
        $reads = array();
        if (!empty($objectIds)) {
            $reads[] = array(
                'ObjectReference.object_id' => array_map('strval', array_keys($objectIds)),
            );
            $reads[] = array(
                'ObjectReference.referenced_type' => 1,
                'ObjectReference.referenced_id' => array_map('strval', array_keys($objectIds)),
            );
        }
        if (!empty($attributeIds)) {
            $reads[] = array(
                'ObjectReference.referenced_type' => 0,
                'ObjectReference.referenced_id' => array_map('strval', array_keys($attributeIds)),
            );
        }
        $rows = array();
        foreach ($reads as $conditions) {
            $found = $reference->find('all', array(
                'conditions' => $conditions + array('ObjectReference.deleted' => 0),
                'fields' => $fields,
                'recursive' => -1,
                'order' => array('ObjectReference.id DESC'),
                'limit' => self::REFERENCE_CAP,
            ));
            foreach ($found as $row) {
                $rows[$row['ObjectReference']['id']] = $row['ObjectReference'];
            }
        }

        $own = function ($row) use ($objectIds, $attributeIds) {
            $source = isset($objectIds[$row['object_id']]);
            $target = (int)$row['referenced_type'] === 1
                ? isset($objectIds[$row['referenced_id']])
                : isset($attributeIds[$row['referenced_id']]);
            return array($source, $target);
        };
        $foreignSources = array();
        foreach ($rows as $id => $row) {
            list($source, $target) = $own($row);
            if ($source && $target) {
                unset($rows[$id]);
            } elseif (!$source) {
                $foreignSources[$row['object_id']] = true;
            }
        }
        if (!empty($foreignSources)) {
            $readable = $this->readableObjectIds(
                $user,
                array_keys($foreignSources)
            );
            foreach ($rows as $id => $row) {
                list($source) = $own($row);
                if (!$source && !isset($readable[$row['object_id']])) {
                    unset($rows[$id]);
                }
            }
        }
        return array_values($rows);
    }

    private function readableObjectIds(array $user, array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $rows = $this->model('MispObject')->fetchObjectSimple($user, array(
            'conditions' => array(
                'Object.id' => array_map('strval', $ids),
                'Object.deleted' => 0,
            ),
            'fields' => array('Object.id'),
        ));
        $readable = array();
        foreach ($rows as $row) {
            $readable[$row['Object']['id']] = true;
        }
        return $readable;
    }

    private function readableAttributeIds(array $user, array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $rows = $this->model('MispAttribute')->fetchAttributesSimple(
            $user,
            array(
                'conditions' => array(
                    'Attribute.id' => array_map('strval', $ids),
                    'Attribute.deleted' => 0,
                ),
                'fields' => array('Attribute.id'),
            )
        );
        $readable = array();
        foreach ($rows as $row) {
            $readable[$row['Attribute']['id']] = true;
        }
        return $readable;
    }

    /**
     * Which of these uuids a relationship the user may read starts or
     * ends at.
     */
    private function relationshipUuids(array $user, array $uuids)
    {
        if (empty($uuids)) {
            return array();
        }
        $relationship = $this->model('Relationship');
        $acl = $relationship->buildConditions($user);
        $found = array();
        foreach (array('object_uuid', 'related_object_uuid') as $end) {
            foreach (array_chunk($uuids, 500) as $chunk) {
                $conditions = array('Relationship.' . $end => $chunk);
                if (!empty($acl)) {
                    $conditions['AND'][] = $acl;
                }
                $rows = $relationship->find('all', array(
                    'conditions' => $conditions,
                    'fields' => array('Relationship.' . $end),
                    'recursive' => -1,
                    'callbacks' => false,
                ));
                foreach ($rows as $row) {
                    $found[$row['Relationship'][$end]] = true;
                }
            }
        }
        return array_keys($found);
    }

    /**
     * Linked units first, then the rest, each newest first.
     */
    private function pick(array $units, array $linked, $budget)
    {
        $first = array_intersect_key($units, $linked);
        $rest = array_diff_key($units, $linked);
        return array_slice($first + $rest, 0, $budget, true);
    }

    /**
     * The units as an event payload slice.
     *
     * @param array $user
     * @param array $units
     * @param bool $withReferences also the references around them, and
     *             what they reach
     * @return array
     */
    private function slice(array $user, array $units, $withReferences)
    {
        $objectIds = array();
        $attributeIds = array();
        $holds = array();
        foreach ($units as $unit) {
            if ($unit['kind'] === 'object') {
                $objectIds[$unit['id']] = true;
                $holds[$unit['uuid']] = array_values($unit['holds']);
            } else {
                $attributeIds[$unit['id']] = true;
            }
        }
        $objects = $this->objects($user, array_keys($objectIds));
        foreach ($objects as $uuid => $object) {
            $objects[$uuid]['holds'] = isset($holds[$uuid]) ? $holds[$uuid] : array();
        }
        $attributes = $this->attributes($user, array_keys($attributeIds));

        $references = array();
        $far = array('objects' => array(), 'attributes' => array());
        if ($withReferences) {
            list($references, $far) = $this->references(
                $user,
                $objects,
                $attributes
            );
        }

        $this->attachRelationships(
            $user,
            $objects,
            $attributes
        );

        $eventIds = array();
        foreach (array_merge(array_values($objects), $far['objects']) as $object) {
            $eventIds[$object['event_id']] = true;
        }
        foreach (array_merge($attributes, $far['attributes']) as $attribute) {
            $eventIds[$attribute['event_id']] = true;
        }
        $events = $this->model('Event')->correlatedEventCards(
            $user,
            array_map('strval', array_keys($eventIds))
        );
        $priorities = $this->model('ObjectTemplate')->uiPrioritiesFor(
            array_merge(array_values($objects), array_values($far['objects']))
        );

        $out = array(
            'Object' => array_values($objects),
            'Attribute' => $attributes,
            'events' => $events ?: new stdClass(),
            'ui_priorities' => $priorities ?: new stdClass(),
        );
        if ($withReferences) {
            $out['references'] = $references;
            $out['far'] = array(
                'objects' => array_values($far['objects']),
                'attributes' => $far['attributes'],
            );
        }
        return $out;
    }

    private function objects(array $user, array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $objects = $this->model('MispObject')->fetchGraphObjects($user, array(
            'Object.id' => array_map('strval', $ids),
        ));
        $order = array_flip(array_map('intval', $ids));
        uasort($objects, function ($a, $b) use ($order) {
            return $order[(int)$a['id']] - $order[(int)$b['id']];
        });
        return $objects;
    }

    /**
     * Attributes as fetchGraphObjects() shapes an object's: with their
     * tags and warninglist hits.
     */
    private function attributes(array $user, array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $out = $this->model('MispAttribute')->fetchGraphAttributes($user, array(
            'Attribute.id' => array_map('strval', $ids),
        ));
        $order = array_flip(array_map('intval', $ids));
        usort($out, function ($a, $b) use ($order) {
            return $order[(int)$a['id']] - $order[(int)$b['id']];
        });
        return $out;
    }

    /**
     * The references reaching out of the drawn units, and their far ends
     * outside them.
     */
    private function references(array $user, array $objects, array $attributes)
    {
        $objectIds = array();
        foreach ($objects as $object) {
            $objectIds[$object['id']] = true;
        }
        $attributeIds = array();
        foreach ($attributes as $attribute) {
            $attributeIds[$attribute['id']] = true;
        }
        foreach ($objects as $object) {
            foreach ($object['holds'] as $uuid) {
                foreach ($object['Attribute'] as $attribute) {
                    if ($attribute['uuid'] === $uuid) {
                        $attributeIds[$attribute['id']] = true;
                    }
                }
            }
        }
        $rows = $this->referenceRows($user, $objectIds, $attributeIds);

        $wantObjects = array();
        $wantAttributes = array();
        foreach ($rows as $row) {
            if (!isset($objectIds[$row['object_id']])) {
                $wantObjects[$row['object_id']] = true;
            }
            if ((int)$row['referenced_type'] === 1) {
                if (!isset($objectIds[$row['referenced_id']])) {
                    $wantObjects[$row['referenced_id']] = true;
                }
            } elseif (!isset($attributeIds[$row['referenced_id']])) {
                $wantAttributes[$row['referenced_id']] = true;
            }
        }
        $farObjects = $this->objects($user, array_keys($wantObjects));
        $farAttributes = $this->attributes($user, array_keys($wantAttributes));
        $readableObjects = array();
        foreach (array_merge(array_values($objects), array_values($farObjects)) as $o) {
            $readableObjects[$o['id']] = true;
        }
        $readableAttributes = $attributeIds;
        foreach ($farAttributes as $a) {
            $readableAttributes[$a['id']] = true;
        }
        foreach ($farObjects as $o) {
            foreach ($o['Attribute'] as $a) {
                $readableAttributes[$a['id']] = true;
            }
        }

        $uuidOf = array();
        foreach (array_merge(array_values($objects), array_values($farObjects)) as $o) {
            $uuidOf[$o['id']] = $o['uuid'];
        }
        $references = array();
        foreach ($rows as $row) {
            $toObject = (int)$row['referenced_type'] === 1;
            $reachable = isset($readableObjects[$row['object_id']])
                && ($toObject
                    ? isset($readableObjects[$row['referenced_id']])
                    : isset($readableAttributes[$row['referenced_id']]));
            if (!$reachable) {
                continue;
            }
            $references[] = array(
                'uuid' => $row['uuid'],
                'object_uuid' => $uuidOf[$row['object_id']],
                'referenced_uuid' => $row['referenced_uuid'],
                'referenced_type' => $toObject ? 'object' : 'attribute',
                'relationship_type' => $row['relationship_type'],
            );
        }
        return array($references, array(
            'objects' => $farObjects,
            'attributes' => $farAttributes,
        ));
    }

    /**
     * Relationship and RelationshipInbound on each record, as the event
     * payload carries them.
     */
    private function attachRelationships(array $user, array &$objects,
        array &$attributes
    ) {
        $uuids = array('Object' => array(), 'Attribute' => array());
        foreach ($objects as $object) {
            $uuids['Object'][] = $object['uuid'];
            foreach ($object['Attribute'] as $attribute) {
                $uuids['Attribute'][] = $attribute['uuid'];
            }
        }
        foreach ($attributes as $attribute) {
            $uuids['Attribute'][] = $attribute['uuid'];
        }
        $all = array_merge($uuids['Object'], $uuids['Attribute']);
        $touched = array_flip($this->relationshipUuids($user, $all));
        if (empty($touched)) {
            return;
        }
        $relationship = $this->model('Relationship');
        $wanted = array_values(array_intersect($all, array_keys($touched)));
        $outbound = $relationship->fetchForUuids($wanted, $user);
        $inbound = array();
        foreach ($uuids as $type => $list) {
            $list = array_values(array_intersect($list, $wanted));
            if (!empty($list)) {
                $inbound += $relationship->getInboundRelationshipsForUuids(
                    $user,
                    $type,
                    $list
                );
            }
        }
        $decorate = function (array &$record) use ($outbound, $inbound) {
            $uuid = $record['uuid'];
            if (!empty($outbound[$uuid]['Relationship'])) {
                $record['Relationship'] = $outbound[$uuid]['Relationship'];
            }
            if (!empty($inbound[$uuid])) {
                $record['RelationshipInbound'] = $inbound[$uuid];
            }
        };
        foreach ($objects as &$object) {
            $decorate($object);
            foreach ($object['Attribute'] as &$attribute) {
                $decorate($attribute);
            }
            unset($attribute);
        }
        unset($object);
        foreach ($attributes as &$attribute) {
            $decorate($attribute);
        }
        unset($attribute);
    }

    /**
     * The feeds and servers holding the value, keyed by id as the event
     * payload's `Feed` and `Server` are.
     */
    private function sources(array $user, $value, array $types)
    {
        $feed = $this->model('Feed');
        $probe = array();
        foreach (Value::asTypes($types) as $type) {
            $probe[] = array(
                'type' => is_array($type) ? $type['type'] : $type,
                'value' => $value,
            );
        }
        $out = array('Feed' => array(), 'Server' => array());
        if (empty($probe)) {
            return $out;
        }
        foreach (array('Feed', 'Server') as $scope) {
            $event = array();
            $feed->attachFeedCorrelations($probe, $user, $event, false, $scope);
            if (!empty($event[$scope])) {
                $out[$scope] = array_values($event[$scope]);
            }
        }
        return $out;
    }

    /**
     * Values close to this one without being equal, one row per value,
     * capped per engine.
     */
    private function near(array $user, $value)
    {
        $profile = $this->model('ValueIntelligence')->forRelationNearMatch(
            $user,
            $value
        );
        $engines = isset($profile['relationships']['near']['engines'])
            ? $profile['relationships']['near']['engines']
            : array();
        $out = array();
        $seen = array();
        foreach ($engines as $engine) {
            if (empty($engine['rows'])) {
                continue;
            }
            $taken = 0;
            foreach ($engine['rows'] as $row) {
                $near = (string)$row['block'];
                if ($near === '' || $near === $value || isset($seen[$near])) {
                    continue;
                }
                if ($taken++ >= self::NEAR_CAP) {
                    break;
                }
                $seen[$near] = true;
                $out[] = array(
                    'value' => $near,
                    'b64' => ValueUrlTool::encode($near),
                    'engine' => $engine['id'],
                    'closeness' => isset($row['prefix'])
                        ? (int)$row['prefix']
                        : (isset($row['class']) ? $row['class'] : null),
                    'event_id' => isset($row['event']) ? (int)$row['event'] : null,
                );
            }
        }
        return $out;
    }

    /**
     * How many units these values land as, and by template, creator org
     * and year — each facet ignoring its own narrowing.
     */
    private function count(array $user, array $values, array $filters,
        array $exclude
    ) {
        $unit = 'COUNT(DISTINCT IF(Attribute.object_id > 0,'
            . " CONCAT('o', Attribute.object_id),"
            . " CONCAT('a', Attribute.id)))";
        $groups = array(
            'template' => 'IF(Attribute.object_id > 0, Object.name, \'\')',
            'org' => "CONCAT('', Event.orgc_id)",
            'year' => 'YEAR(FROM_UNIXTIME(Attribute.timestamp))',
        );
        $attributes = $this->model('MispAttribute');
        $out = array('total' => 0);
        foreach ($groups as $facet => $expression) {
            $narrowed = $filters;
            unset($narrowed[$facet]);
            $counts = array();
            foreach ($values as $value) {
                $rows = $attributes->find('all', array(
                    'conditions' => $this->conditions(
                        $user,
                        $value,
                        $narrowed,
                        $exclude
                    ),
                    'fields' => array(
                        $expression . ' AS bucket',
                        $unit . ' AS units',
                    ),
                    'contain' => array('Event', 'Object'),
                    'group' => array('bucket'),
                    'order' => false,
                ));
                foreach ($rows as $row) {
                    $bucket = (string)$row[0]['bucket'];
                    $counts[$bucket] = (isset($counts[$bucket]) ? $counts[$bucket] : 0)
                        + (int)$row[0]['units'];
                }
            }
            arsort($counts);
            $out['by_' . $facet] = $counts;
        }
        if (!empty($out['by_org'])) {
            $names = $this->model('Organisation')->find('list', array(
                'conditions' => array(
                    'Organisation.id' => array_map('strval', array_keys($out['by_org'])),
                ),
                'fields' => array('Organisation.id', 'Organisation.name'),
                'recursive' => -1,
            ));
            $named = array();
            foreach ($out['by_org'] as $id => $n) {
                $named[] = array(
                    'id' => (int)$id,
                    'name' => isset($names[$id]) ? $names[$id] : (string)$id,
                    'count' => $n,
                );
            }
            $out['by_org'] = $named;
        }
        $templateFilter = isset($filters['template']) ? $filters['template'] : null;
        $total = 0;
        foreach ($out['by_template'] as $name => $n) {
            if (empty($templateFilter) || in_array((string)$name, array_map('strval', (array)$templateFilter), true)) {
                $total += $n;
            }
        }
        $out['total'] = $total;
        return $out;
    }
}
