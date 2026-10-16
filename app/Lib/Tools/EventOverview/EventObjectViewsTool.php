<?php
App::uses('EventOverviewTool', 'Tools/EventOverview');
App::uses('ValueRendererTool', 'Tools/ValueIntelligence');

/**
 * The Value Intelligence renderers drawn from an event's own objects, for
 * the Overmind event overview.
 *
 * Only renderers declaring `$eventUse` take part. Each template is read
 * newest first and capped at OBJECT_CAP objects, attributes are capped at
 * ATTRIBUTE_CAP in all, and every read applies MISP's own ACL conditions.
 */
class EventObjectViewsTool
{
    const OBJECT_CAP = 200;

    const ATTRIBUTE_CAP = 20000;

    /** Subjects drawn per `each` shape. */
    const SUBJECT_CAP = 50;

    const INDEX = 'idx_event_deleted_name';

    /** Files the map opens: template => the relation holding them. */
    const MAP_FILES = array(
        'gpx' => 'attachment',
        'geojson' => 'attachment',
        'uav' => 'flight-path',
    );

    /** Relations that name an object, in preference order. */
    const LABELS = array(
        'name', 'filename', 'sha256', 'sha1', 'md5', 'ip', 'ip-src',
        'ip-dst', 'domain', 'hostname', 'url', 'address', 'wallet-address',
    );

    /** @var EventOverviewTool */
    private $overview;

    /** @var Model */
    private $Object;

    /** @var Model */
    private $Attribute;

    /** @var Model */
    private $ObjectReference;

    /** @var string|null */
    private $hint = null;

    public function __construct()
    {
        $this->overview = new EventOverviewTool();
        $this->Object = ClassRegistry::init('MispObject');
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->ObjectReference = ClassRegistry::init('ObjectReference');
    }

    /**
     * The view model for one event page.
     *
     * @param array $user
     * @param array $events Event rows (id, org_id, timestamp), the viewed
     *        event first, then any events extending it
     * @return array
     */
    public function views(array $user, array $events)
    {
        $viewed = $events[0];
        $parts = array();
        foreach ($events as $event) {
            $parts[] = (int)$event['id'] . '-' . (int)$event['timestamp']
                . '-' . $this->overview->scope($user, $event)['key'];
        }
        $kind = 'object-views-v4:' . md5(implode(',', $parts));
        $views = $this->overview->cached(
            $kind,
            $viewed,
            $this->overview->scope($user, $viewed),
            function () use ($user, $events) {
                return $this->compute($user, $events);
            }
        );
        $tiles = (bool)Configure::read('Plugin.Geolocation_enabled');
        $views['map']['tiles'] = $tiles;
        $views['map']['tile_url'] = $tiles
            ? (Configure::read('Plugin.Geolocation_url') ?: 'https://geo.circl.lu')
            : null;
        $renderers = ValueRendererTool::renderers();
        foreach ($views['shapes'] as &$shape) {
            if ($shape['use'] === ValueRendererBase::EVENT_EACH && isset($renderers[$shape['shape']])) {
                $shape['words'] = $renderers[$shape['shape']]->subjectWords();
            }
        }
        unset($shape);
        return $views;
    }

    private function compute(array $user, array $events)
    {
        $renderers = array_filter(
            ValueRendererTool::renderers(),
            function ($renderer) {
                return $renderer->eventUse !== null;
            }
        );
        $claims = array();
        foreach ($renderers as $id => $renderer) {
            foreach ($renderer->templates as $template) {
                $claims[$template] = $id;
            }
        }
        $wanted = $claims + array_fill_keys(array_keys(self::MAP_FILES), null);

        $objects = array();
        $templates = array();
        $origins = array();
        $files = array();
        $budget = self::ATTRIBUTE_CAP;
        $attributesCapped = false;
        foreach ($events as $event) {
            $counts = $this->overview->objectCounts($user, $event['id'])['by_name'];
            foreach (array_intersect_key($counts, $wanted) as $template => $total) {
                $rows = $this->objectRows($user, $event['id'], $template);
                if (!isset($templates[$template])) {
                    $templates[$template] = array('total' => 0, 'read' => 0);
                }
                $templates[$template]['total'] += (int)$total;
                $templates[$template]['read'] += count($rows);
                if (empty($rows)) {
                    continue;
                }
                $attributes = array();
                if ($budget > 0) {
                    $attributes = $this->attributeRows($user, array_keys($rows), $budget + 1);
                }
                if (count($attributes) > $budget) {
                    $attributes = array_slice($attributes, 0, $budget);
                    $attributesCapped = true;
                } elseif ($budget <= 0) {
                    $attributesCapped = true;
                }
                $budget -= count($attributes);
                $byObject = array();
                foreach ($attributes as $attribute) {
                    $byObject[(int)$attribute['object_id']][] = $attribute;
                }
                foreach ($rows as $objectId => $object) {
                    $object['Attribute'] = $byObject[$objectId] ?? array();
                    $uuid = $object['uuid'];
                    $origins[$uuid] = array(
                        'object_id' => (int)$object['id'],
                        'event_id' => (int)$object['event_id'],
                        'template' => $template,
                        'label' => $this->labelOf($object['Attribute']),
                    );
                    if (isset(self::MAP_FILES[$template])) {
                        foreach ($this->filesOf($object, self::MAP_FILES[$template]) as $file) {
                            $files[] = $file;
                        }
                    }
                    if (isset($claims[$template])) {
                        $shaped = ValueRendererTool::shapeObject($object);
                        $shaped['module'] = $uuid;
                        $shaped['ran_at'] = (int)$object['timestamp'];
                        $objects[$claims[$template]][] = $shaped;
                    }
                }
            }
        }

        $shapes = array();
        foreach ($objects as $id => $list) {
            $shape = $this->draw($renderers[$id], $list, $templates);
            if ($shape !== null) {
                $shapes[] = $shape;
            }
        }
        $shapes = $this->withNeighbours($user, $shapes, $origins);
        usort($shapes, function ($a, $b) {
            return array($b['objects'], $a['shape']) <=> array($a['objects'], $b['shape']);
        });
        $used = array_column($files, 'origin');
        foreach ($shapes as $shape) {
            foreach ($shape['drawings'] as $drawing) {
                $used = array_merge($used, $drawing['origins']);
            }
        }
        return array(
            'shapes' => $shapes,
            'map' => array('files' => $files),
            'origins' => array_intersect_key($origins, array_flip($used)),
            'attributes_capped' => $attributesCapped,
        );
    }

    /**
     * @param ValueRendererBase $renderer
     * @param array $objects Shaped objects claiming this renderer
     * @param array $templates template => total/read
     * @return array|null
     */
    private function draw($renderer, array $objects, array $templates)
    {
        $mine = array_intersect_key($templates, array_flip($renderer->templates));
        $capped = false;
        foreach ($mine as $counts) {
            $capped = $capped || $counts['read'] < $counts['total'];
        }
        $shape = array(
            'shape' => $renderer->id,
            'use' => $renderer->eventUse,
            'description' => $renderer->description,
            'compact' => $renderer->compact,
            'full' => $renderer->full,
            'templates' => $mine,
            'objects' => count($objects),
            'capped' => $capped,
        );
        if ($renderer->eventUse === ValueRendererBase::EVENT_SET) {
            if (!$renderer->matches($objects, array())) {
                return null;
            }
            $shape['drawings'] = array($this->drawing($renderer, null, $objects));
            return $shape;
        }
        $drawable = array();
        foreach ($renderer->groupsOf($objects) as $group) {
            if ($renderer->matches($group['objects'], array())) {
                $drawable[] = $group;
            }
        }
        if (empty($drawable)) {
            return null;
        }
        $shape['subjects'] = array(
            'total' => count($drawable),
            'drawn' => min(count($drawable), self::SUBJECT_CAP),
        );
        $shape['drawings'] = array();
        foreach (array_slice($drawable, 0, self::SUBJECT_CAP) as $group) {
            $drawing = $this->drawing($renderer, $group['subject'], $group['objects']);
            $drawing['subject_kind'] = $group['kind'] ?? ($group['subject'] === null
                ? ValueRendererBase::SUBJECT_OWN : ValueRendererBase::SUBJECT_NAMED);
            $shape['drawings'][] = $drawing;
        }
        return $shape;
    }

    private function drawing($renderer, $subject, array $objects)
    {
        return array(
            'subject' => $subject,
            'origins' => array_values(array_unique(array_column($objects, 'module'))),
            'data' => $renderer->prepare($objects, array()),
        );
    }

    private static function ownSubject(array $drawing)
    {
        return ($drawing['subject_kind'] ?? null) === ValueRendererBase::SUBJECT_OWN
            && count($drawing['origins']) === 1;
    }

    /**
     * Names the subject of a one-object drawing whose renderer could not, by
     * the one object it references or is referenced by (a virustotal-report
     * is attached to its file by `analysed-with`).
     */
    private function withNeighbours(array $user, array $shapes, array $origins)
    {
        $wanted = array();
        foreach ($shapes as $shape) {
            foreach ($shape['drawings'] as $drawing) {
                if (self::ownSubject($drawing)) {
                    $wanted[$origins[$drawing['origins'][0]]['object_id']] = true;
                }
            }
        }
        if (empty($wanted)) {
            return $shapes;
        }
        $ids = array_keys($wanted);
        $links = array();
        foreach (array(array('object_id', 'referenced_id'), array('referenced_id', 'object_id')) as $pair) {
            list($mine, $theirs) = $pair;
            $rows = $this->ObjectReference->find('all', array(
                'recursive' => -1,
                'fields' => array('ObjectReference.' . $mine, 'ObjectReference.' . $theirs),
                'conditions' => array(
                    'ObjectReference.' . $mine => $ids,
                    'ObjectReference.referenced_type' => 1,
                    'ObjectReference.deleted' => 0,
                ),
            ));
            foreach ($rows as $row) {
                $links[(int)$row['ObjectReference'][$mine]][(int)$row['ObjectReference'][$theirs]] = true;
            }
        }
        $neighbourOf = array();
        foreach ($links as $objectId => $others) {
            if (count($others) === 1) {
                $neighbourOf[$objectId] = (int)key($others);
            }
        }
        $neighbours = $this->describeObjects($user, array_unique(array_values($neighbourOf)));
        foreach ($shapes as &$shape) {
            foreach ($shape['drawings'] as &$drawing) {
                if (!self::ownSubject($drawing)) {
                    continue;
                }
                $objectId = $origins[$drawing['origins'][0]]['object_id'];
                $neighbour = $neighbourOf[$objectId] ?? null;
                if ($neighbour !== null && isset($neighbours[$neighbour])) {
                    $drawing['neighbour'] = $neighbours[$neighbour];
                }
            }
            unset($drawing);
        }
        unset($shape);
        return $shapes;
    }

    /**
     * @param array $user
     * @param array $ids Object ids
     * @return array id => object_id, event_id, template, label (visible ones only)
     */
    private function describeObjects(array $user, array $ids)
    {
        if (empty($ids)) {
            return array();
        }
        $rows = $this->Object->fetchObjectSimple($user, array(
            'conditions' => array('Object.id' => $ids),
            'fields' => array('Object.id', 'Object.event_id', 'Object.name'),
        ));
        $out = array();
        foreach ($rows as $row) {
            $out[(int)$row['Object']['id']] = array(
                'object_id' => (int)$row['Object']['id'],
                'event_id' => (int)$row['Object']['event_id'],
                'template' => $row['Object']['name'],
                'label' => null,
            );
        }
        if (empty($out)) {
            return $out;
        }
        $attributes = $this->Attribute->fetchAttributesSimple($user, array(
            'conditions' => array(
                'Attribute.object_id' => array_keys($out),
                'Attribute.deleted' => 0,
                'Attribute.object_relation' => self::LABELS,
            ),
            'fields' => array('Attribute.object_id', 'Attribute.object_relation', 'Attribute.value'),
            'contain' => array('Event' => array('fields' => array('Event.id')), 'Object' => array('fields' => array('Object.id'))),
            'limit' => count($out) * count(self::LABELS),
        ));
        $byObject = array();
        foreach ($attributes as $row) {
            $byObject[(int)$row['Attribute']['object_id']][] = $row['Attribute'];
        }
        foreach ($byObject as $objectId => $list) {
            $out[$objectId]['label'] = $this->labelOf($list);
        }
        return $out;
    }

    /**
     * One template's newest live objects in one event, as far as the user
     * may read them, keyed by id.
     */
    private function objectRows(array $user, $eventId, $template)
    {
        $rows = $this->Object->query(
            'SELECT Object.id, Object.uuid, Object.event_id, Object.name, Object.`meta-category`,'
            . ' Object.description, Object.comment, Object.timestamp'
            . ' FROM objects Object ' . $this->indexHint() . ' JOIN events Event ON Event.id = Object.event_id'
            . ' WHERE Object.event_id = ? AND Object.deleted = 0 AND Object.name = ?'
            . ' AND ' . $this->overview->aclSql($user, 'Object')
            . ' ORDER BY Object.id DESC LIMIT ' . self::OBJECT_CAP,
            array($eventId, $template),
            false
        );
        $out = array();
        foreach ($rows as $row) {
            $out[(int)$row['Object']['id']] = $row['Object'];
        }
        return $out;
    }

    /**
     * Pinned to (event_id, deleted, name): without it the planner can merge
     * the event_id and name indexes, walking every object of both.
     */
    private function indexHint()
    {
        if ($this->hint === null) {
            $indexes = $this->Object->getDataSource()->index($this->Object);
            $index = isset($indexes[self::INDEX]) ? self::INDEX : 'event_id';
            $this->hint = 'FORCE INDEX (' . $index . ')';
        }
        return $this->hint;
    }

    private function attributeRows(array $user, array $objectIds, $limit)
    {
        $rows = $this->Attribute->fetchAttributesSimple($user, array(
            'conditions' => array(
                'Attribute.object_id' => $objectIds,
                'Attribute.deleted' => 0,
            ),
            'fields' => array(
                'Attribute.id', 'Attribute.object_id', 'Attribute.object_relation', 'Attribute.type',
                'Attribute.category', 'Attribute.value', 'Attribute.comment', 'Attribute.to_ids',
                'Attribute.disable_correlation',
            ),
            'contain' => array('Event' => array('fields' => array('Event.id')), 'Object' => array('fields' => array('Object.id'))),
            'limit' => $limit,
        ));
        return array_column($rows, 'Attribute');
    }

    private function filesOf(array $object, $relation)
    {
        $out = array();
        foreach ($object['Attribute'] as $attribute) {
            if ($attribute['object_relation'] === $relation && $attribute['type'] === 'attachment') {
                $out[] = array(
                    'origin' => $object['uuid'],
                    'template' => $object['name'],
                    'attachment' => (int)$attribute['id'],
                    'name' => $attribute['value'],
                );
            }
        }
        return $out;
    }

    /**
     * A label cut in the middle, so a hash keeps both ends and a file name
     * its extension.
     *
     * @param string $text
     * @param int $max characters
     * @return string
     */
    public static function shorten($text, $max)
    {
        $chars = preg_split('//u', (string)$text, -1, PREG_SPLIT_NO_EMPTY);
        if ($chars === false || count($chars) <= $max) {
            return (string)$text;
        }
        $head = (int)ceil(($max - 1) * 0.6);
        $tail = $max - 1 - $head;
        return implode('', array_slice($chars, 0, $head)) . '…'
            . implode('', array_slice($chars, -$tail));
    }

    private function labelOf(array $attributes)
    {
        $byRelation = array();
        foreach ($attributes as $attribute) {
            if (!isset($byRelation[$attribute['object_relation']]) && $attribute['value'] !== '') {
                $byRelation[$attribute['object_relation']] = $attribute['value'];
            }
        }
        foreach (self::LABELS as $relation) {
            if (isset($byRelation[$relation])) {
                return $byRelation[$relation];
            }
        }
        return null;
    }
}
