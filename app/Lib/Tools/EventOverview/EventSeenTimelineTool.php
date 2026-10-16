<?php
App::uses('EventOverviewTool', 'Tools/EventOverview');
App::uses('ValueIntelligenceBuckets', 'Tools/ValueIntelligence');

/**
 * The data behind the Overmind event Timeline tab: loose attributes and
 * objects placed by first_seen / last_seen, or by their timestamp, an object
 * spanning its own dates and its attributes'.
 *
 * Under the seen basis a row is dated when it has either end; under the
 * timestamp basis it is a single instant. An undated row is counted, never
 * placed. Dates are microseconds; days are UTC days since the epoch.
 *
 * Every query is scoped to the events asked for. Visibility is MISP's own
 * read conditions (`EventOverviewTool::aclSql()`), part of the SQL because
 * the row queries are cut with a LIMIT.
 */
class EventSeenTimelineTool
{
    /** Rows returned for one window, past which the response says it is capped. */
    const ITEM_CAP = 2000;

    /** Dated attributes of the returned objects, past which they are fetched per object. */
    const CHILD_INLINE_CAP = 2000;

    /** Dated attributes returned for a single object. */
    const CHILD_CAP = 500;

    const LABEL_MAX = 200;

    const DAY_US = 86400000000;

    const BASIS_SEEN = 'seen';

    const BASIS_TIMESTAMP = 'timestamp';

    /** How far past today the histogram reaches before calling dates outside. */
    const SPAN_AHEAD_DAYS = 3653;

    /** The widest span the histogram draws, back from its end. */
    const SPAN_MAX_DAYS = 18263;

    /** @var EventOverviewTool */
    private $overview;

    /** @var Model */
    private $Attribute;

    /** @var Model */
    private $Object;

    public function __construct(EventOverviewTool $overview = null)
    {
        $this->overview = $overview ?? new EventOverviewTool();
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $this->Object = ClassRegistry::init('MispObject');
    }

    /**
     * @param array $user
     * @param array $events Event rows (id, org_id, timestamp), the viewed one first
     * @param array $options basis, from, to (`Y-m-d`, inclusive), q, kind,
     *        types, objects, categories, events
     * @param string $today `Y-m-d`
     * @return array basis, span, histogram, window, items, capped, in_window,
     *         counts, facets
     */
    public function timeline(array $user, array $events, array $options, $today)
    {
        $basis = self::basis($options);
        $tallies = [];
        foreach ($events as $event) {
            $tallies[(int)$event['id']] = $this->tally($user, $event, $basis);
        }
        $merged = self::mergeTallies($tallies);
        $histogram = self::histogram($merged['starts'], $merged['ends'], $today);

        $window = self::window($options, $histogram);
        $items = [];
        $capped = false;
        $inWindow = 0;
        if ($window !== null) {
            $acl = $this->acl($user, self::filterEvents(array_column($events, 'id'), $options['events'] ?? []));
            list($items, $capped, $inWindow) = $this->items($acl, $window, $options);
        }

        return [
            'basis' => $basis,
            'span' => $histogram === null ? null : [
                'from' => $histogram['from'],
                'to' => $histogram['to'],
            ],
            'histogram' => $histogram,
            'window' => $window === null ? null : [
                'from' => gmdate('Y-m-d', $window[0] * 86400),
                'to' => gmdate('Y-m-d', $window[1] * 86400),
            ],
            'items' => $items,
            'capped' => $capped,
            'in_window' => $inWindow,
            'counts' => [
                'attributes' => $merged['attributes'],
                'objects' => $merged['objects'],
                'dated' => $merged['attributes'] + $merged['objects'],
                'undated' => $merged['undated'],
                'undated_attributes' => $merged['undated_attributes'],
                'undated_objects' => $merged['undated_objects'],
                'outside' => $histogram['outside'] ?? 0,
            ],
            'facets' => array_map(function ($counts) {
                return (object)$counts;
            }, $merged['facets']),
        ];
    }

    /**
     * The dated attributes of one object, for an object whose children were
     * not inlined.
     *
     * @param array $user
     * @param array $events Event rows the object may belong to
     * @param int $objectId
     * @param array $options basis
     * @return array|null children, capped; null when the object is not visible
     */
    public function objectChildren(array $user, array $events, $objectId, array $options = [])
    {
        $acl = $this->acl($user, array_column($events, 'id'));
        list(, $o, $e) = $this->overview->aliases();
        $objects = $this->rows(
            "SELECT $o.id FROM objects $o JOIN events $e ON $e.id = $o.event_id"
            . " WHERE $o.id = ? AND $o.event_id IN (" . $acl['events'] . ") AND $o.deleted = FALSE"
            . ' AND ' . $acl['object'],
            [(int)$objectId]
        );
        if (empty($objects)) {
            return null;
        }
        $children = $this->children($acl, self::basis($options), [(int)$objectId], self::CHILD_CAP + 1);
        $rows = $children[(int)$objectId] ?? [];
        return [
            'children' => array_slice($rows, 0, self::CHILD_CAP),
            'capped' => count($rows) > self::CHILD_CAP,
        ];
    }

    /**
     * The events' ids as an SQL list and the user's read conditions over
     * `Attribute`, `Object` and `Event`.
     */
    private function acl(array $user, array $eventIds)
    {
        $eventIds = array_map('intval', $eventIds);
        return [
            'events' => empty($eventIds) ? '0' : implode(', ', $eventIds),
            'attribute' => $this->overview->aclSql($user, 'Attribute'),
            'object' => $this->overview->aclSql($user, 'Object'),
        ];
    }

    /**
     * Start and end days, undated count and facet counts for one event,
     * cached on the event's timestamp and the reader's scope.
     */
    private function tally(array $user, array $event, $basis)
    {
        $scope = $this->overview->scope($user, $event);
        return $this->overview->cached('timeline-v4-' . $basis, $event, $scope, function () use ($user, $event, $basis) {
            return $this->computeTally($this->acl($user, [(int)$event['id']]), $basis);
        });
    }

    private function computeTally(array $acl, $basis)
    {
        $tally = [
            'starts' => [], 'ends' => [], 'attributes' => 0, 'objects' => 0, 'undated' => 0,
            'undated_attributes' => 0, 'undated_objects' => 0,
            'facets' => ['types' => [], 'objects' => [], 'categories' => []],
        ];
        list($a) = $this->overview->aliases();
        $loose = $this->looseFrom($acl);
        $objects = '(' . $this->envelopeSql($acl, $basis) . ') env';
        foreach (['starts' => 's', 'ends' => 'e'] as $key => $column) {
            $source = [
                'attributes' => 'SELECT FLOOR(' . self::dateSql($basis, $a, $column) . ' / ' . self::DAY_US . ') AS d,'
                    . ' COUNT(*) AS n ' . $loose . ' GROUP BY d',
                'objects' => 'SELECT FLOOR(env.' . $column . ' / ' . self::DAY_US . ') AS d, COUNT(*) AS n'
                    . ' FROM ' . $objects . ' GROUP BY d',
            ];
            foreach ($source as $kind => $sql) {
                foreach ($this->rows($sql) as $r) {
                    if ($r['d'] === null) {
                        if ($key === 'starts') {
                            $tally['undated'] += (int)$r['n'];
                            $tally['undated_' . $kind] += (int)$r['n'];
                        }
                        continue;
                    }
                    $day = (int)$r['d'];
                    $tally[$key][$day] = ($tally[$key][$day] ?? 0) + (int)$r['n'];
                    if ($key === 'starts') {
                        $tally[$kind] += (int)$r['n'];
                    }
                }
            }
        }
        $facets = [
            ['types', 'type', "SELECT $a.type AS f, $a.category AS c, COUNT(*) AS n " . $loose
                . ' AND ' . self::datedSql($basis, $a) . " GROUP BY $a.type, $a.category"],
            ['objects', 'name', 'SELECT env.name AS f, env.category AS c, COUNT(*) AS n FROM ' . $objects
                . ' WHERE env.s IS NOT NULL GROUP BY env.name, env.category'],
        ];
        foreach ($facets as list($facet, , $sql)) {
            foreach ($this->rows($sql) as $r) {
                $n = (int)$r['n'];
                $tally['facets'][$facet][$r['f']] = ($tally['facets'][$facet][$r['f']] ?? 0) + $n;
                $category = (string)$r['c'];
                $tally['facets']['categories'][$category] = ($tally['facets']['categories'][$category] ?? 0) + $n;
            }
        }
        return $tally;
    }

    /**
     * Several events' tallies as one, with the dated rows per event as a facet.
     *
     * @param array $tallies event id => tally
     * @return array
     */
    public static function mergeTallies(array $tallies)
    {
        $merged = [
            'starts' => [], 'ends' => [], 'attributes' => 0, 'objects' => 0, 'undated' => 0,
            'undated_attributes' => 0, 'undated_objects' => 0,
            'facets' => ['types' => [], 'objects' => [], 'categories' => [], 'events' => []],
        ];
        foreach ($tallies as $eventId => $tally) {
            foreach (['starts', 'ends'] as $key) {
                foreach ($tally[$key] as $day => $n) {
                    $merged[$key][$day] = ($merged[$key][$day] ?? 0) + $n;
                }
            }
            foreach (['attributes', 'objects', 'undated', 'undated_attributes', 'undated_objects'] as $key) {
                $merged[$key] += $tally[$key] ?? 0;
            }
            foreach ($tally['facets'] as $facet => $counts) {
                foreach ($counts as $name => $n) {
                    $merged['facets'][$facet][$name] = ($merged['facets'][$facet][$name] ?? 0) + $n;
                }
            }
            $merged['facets']['events'][$eventId] = $tally['attributes'] + $tally['objects'];
        }
        foreach (['types', 'objects', 'categories'] as $facet) {
            arsort($merged['facets'][$facet]);
        }
        return $merged;
    }

    /**
     * How many rows are seen in each bucket of the span: a row counts in every
     * bucket between its first and last day, a row with one end only in that
     * end's bucket.
     *
     * The span runs from the earliest day to the latest, but stops
     * SPAN_AHEAD_DAYS past today and reaches back at most SPAN_MAX_DAYS; rows
     * wholly beyond it are counted in `outside`.
     *
     * @param array $starts day => rows starting that day
     * @param array $ends day => rows ending that day
     * @param string $today `Y-m-d`
     * @return array|null from, to, unit, max, bars (from, to, label, count), outside
     */
    public static function histogram(array $starts, array $ends, $today)
    {
        $days = array_merge(array_keys($starts), array_keys($ends));
        if (empty($days)) {
            return null;
        }
        $todayDay = intdiv((int)(new DateTimeImmutable($today . ' 00:00:00', new DateTimeZone('UTC')))
            ->getTimestamp(), 86400);
        $to = min(max($days), $todayDay + self::SPAN_AHEAD_DAYS);
        $from = max(min($days), $to - self::SPAN_MAX_DAYS + 1);
        if ($from > $to) {
            return null;
        }
        $fromDate = gmdate('Y-m-d', $from * 86400);
        $toDate = gmdate('Y-m-d', $to * 86400);
        $unit = ValueIntelligenceBuckets::unitForSpan($to - $from + 1, [
            ['days' => 45, 'unit' => ValueIntelligenceBuckets::DAY],
            ['days' => 370, 'unit' => ValueIntelligenceBuckets::WEEK],
            ['days' => null, 'unit' => ValueIntelligenceBuckets::MONTH],
        ]);
        $series = ValueIntelligenceBuckets::series($fromDate, $toDate, $unit);
        $index = ValueIntelligenceBuckets::locate($series);
        $count = count($series);
        $bucketOf = function ($day) use ($from, $to, $index, $count) {
            if ($day < $from) {
                return -1;
            }
            return $day > $to ? $count : $index[gmdate('Y-m-d', $day * 86400)];
        };

        $delta = array_fill(0, $count + 1, 0);
        $outside = 0;
        foreach ($starts as $day => $n) {
            $bucket = max(0, $bucketOf((int)$day));
            if ($bucket >= $count) {
                $outside += $n;
                continue;
            }
            $delta[$bucket] += $n;
        }
        foreach ($ends as $day => $n) {
            $bucket = $bucketOf((int)$day);
            if ($bucket < 0) {
                $outside += $n;
            }
            if ($bucket < $count) {
                $delta[$bucket + 1] -= $n;
            }
        }

        $bars = [];
        $running = 0;
        $max = 0;
        foreach ($series as $position => $bucket) {
            $running += $delta[$position];
            $max = max($max, $running);
            $bars[] = [
                'from' => $bucket['from'],
                'to' => $bucket['to'],
                'label' => $bucket['title'],
                'count' => $running,
            ];
        }
        return [
            'from' => $fromDate,
            'to' => $toDate,
            'unit' => $unit,
            'max' => $max,
            'bars' => $bars,
            'outside' => $outside,
        ];
    }

    /**
     * The window asked for, clamped to whole days, or the histogram's span.
     *
     * @param array $options from, to (`Y-m-d`)
     * @param array|null $histogram
     * @return array|null [first day, last day]
     */
    public static function window(array $options, $histogram)
    {
        $day = function ($date) {
            if (!is_string($date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) {
                return null;
            }
            $parsed = DateTimeImmutable::createFromFormat('!Y-m-d', $date, new DateTimeZone('UTC'));
            return $parsed === false ? null : intdiv($parsed->getTimestamp(), 86400);
        };
        $from = $day($options['from'] ?? null);
        $to = $day($options['to'] ?? null);
        if ($histogram !== null) {
            $from = $from ?? $day($histogram['from']);
            $to = $to ?? $day($histogram['to']);
        }
        if ($from === null || $to === null) {
            return null;
        }
        return $from <= $to ? [$from, $to] : [$to, $from];
    }

    /**
     * The rows overlapping the window, earliest first, at most ITEM_CAP.
     *
     * @return array [items, capped, rows in window]
     */
    private function items(array $acl, array $window, array $options)
    {
        if ($acl['events'] === '0') {
            return [[], false, 0];
        }
        $basis = self::basis($options);
        $lower = $window[0] * self::DAY_US;
        $upper = ($window[1] + 1) * self::DAY_US - 1;
        $want = self::wanted($options);

        $parts = [];
        if ($want['attributes']) {
            $parts['attributes'] = $this->attributeFilter($acl, $basis, $options, $lower, $upper);
        }
        if ($want['objects']) {
            $parts['objects'] = $this->objectFilter($acl, $basis, $options, $lower, $upper);
        }

        $attributes = $objects = [];
        if (isset($parts['attributes'])) {
            list($sql, $params) = $parts['attributes'];
            list($a) = $this->overview->aliases();
            $attributes = $this->withValues($this->rows(
                "SELECT $a.id, $a.uuid, $a.event_id, $a.type,"
                . " $a.category, $a.to_ids,"
                . " $a.value1_id, $a.value2_id,"
                . " $a.first_seen, $a.last_seen, $a.timestamp,"
                . ' ' . self::dateSql($basis, $a, 's') . ' AS s, '
                . self::dateSql($basis, $a, 'e') . ' AS e ' . $sql
                . " ORDER BY s, $a.id LIMIT " . (self::ITEM_CAP + 1),
                $params
            ));
        }
        if (isset($parts['objects'])) {
            list($sql, $params) = $parts['objects'];
            $objects = $this->rows(
                'SELECT env.* ' . $sql . ' ORDER BY env.s, env.id LIMIT ' . (self::ITEM_CAP + 1),
                $params
            );
        }

        $merged = self::mergeRows($attributes, $objects, self::ITEM_CAP);
        $capped = count($attributes) + count($objects) > self::ITEM_CAP;
        $inWindow = count($merged);
        if ($capped) {
            $inWindow = 0;
            foreach ($parts as $part) {
                list($sql, $params) = $part;
                $inWindow += (int)($this->rows('SELECT COUNT(*) AS n ' . $sql, $params)[0]['n'] ?? 0);
            }
        }

        $objectIds = [];
        $childTotal = 0;
        foreach ($merged as $row) {
            if ($row['kind'] === 'object') {
                $objectIds[] = (int)$row['id'];
                $childTotal += (int)$row['dated_children'];
            }
        }
        $children = [];
        if (!empty($objectIds) && $childTotal <= self::CHILD_INLINE_CAP) {
            $children = $this->children($acl, $basis, $objectIds, self::CHILD_INLINE_CAP + 1);
        }
        $inline = !empty($objectIds) && $childTotal <= self::CHILD_INLINE_CAP;

        $items = [];
        foreach ($merged as $row) {
            if ($row['kind'] === 'attribute') {
                $items[] = self::attributeItem($row);
                continue;
            }
            $item = self::objectItem($row);
            $item['children'] = $inline ? ($children[(int)$row['id']] ?? []) : null;
            $items[] = $item;
        }
        return [$items, $capped, $inWindow];
    }

    /**
     * Two lists already sorted by start, as one, the first $cap of them.
     *
     * @return array rows, each tagged with its kind
     */
    public static function mergeRows(array $attributes, array $objects, $cap)
    {
        $rows = [];
        foreach ($attributes as $row) {
            $rows[] = ['kind' => 'attribute'] + $row;
        }
        foreach ($objects as $row) {
            $rows[] = ['kind' => 'object'] + $row;
        }
        usort($rows, function ($a, $b) {
            return [(int)$a['s'], $a['kind'], (int)$a['id']] <=> [(int)$b['s'], $b['kind'], (int)$b['id']];
        });
        return array_slice($rows, 0, $cap);
    }

    /**
     * Which kinds of row the filter can match: a type picks attributes, an
     * object name picks objects, both pick both.
     */
    public static function wanted(array $options)
    {
        $kind = $options['kind'] ?? null;
        $types = !empty($options['types']);
        $objects = !empty($options['objects']);
        return [
            'attributes' => $kind !== 'object' && ($types || !$objects),
            'objects' => $kind !== 'attribute' && ($objects || !$types),
        ];
    }

    /**
     * The events of the view, narrowed to those asked for.
     */
    public static function filterEvents(array $eventIds, array $wanted)
    {
        $eventIds = array_map('intval', $eventIds);
        if (empty($wanted)) {
            return $eventIds;
        }
        return array_values(array_intersect($eventIds, array_map('intval', $wanted)));
    }

    private function attributeFilter(array $acl, $basis, array $options, $lower, $upper)
    {
        list($a) = $this->overview->aliases();
        $sql = $this->looseFrom($acl) . ' AND ' . self::datedSql($basis, $a)
            . ' AND ' . self::dateSql($basis, $a, 's') . ' <= ? AND ' . self::dateSql($basis, $a, 'e') . ' >= ?';
        $params = [$upper, $lower];
        if (!empty($options['types'])) {
            $sql .= " AND $a.type IN (" . self::placeholders($options['types']) . ')';
            $params = array_merge($params, array_values($options['types']));
        }
        if (!empty($options['categories'])) {
            $sql .= " AND $a.category IN (" . self::placeholders($options['categories']) . ')';
            $params = array_merge($params, array_values($options['categories']));
        }
        if (isset($options['q']) && trim($options['q']) !== '') {
            $like = '%' . self::escapeLike(trim($options['q'])) . '%';
            $sql .= ' AND ' . $this->valueSearchSql($like);
        }
        return [$sql, $params];
    }

    private function objectFilter(array $acl, $basis, array $options, $lower, $upper)
    {
        $sql = 'FROM (' . $this->envelopeSql($acl, $basis) . ') env'
            . ' WHERE env.s IS NOT NULL AND env.s <= ? AND env.e >= ?';
        $params = [$upper, $lower];
        if (!empty($options['objects'])) {
            $sql .= ' AND env.name IN (' . self::placeholders($options['objects']) . ')';
            $params = array_merge($params, array_values($options['objects']));
        }
        if (!empty($options['categories'])) {
            $sql .= ' AND env.category IN (' . self::placeholders($options['categories']) . ')';
            $params = array_merge($params, array_values($options['categories']));
        }
        if (isset($options['q']) && trim($options['q']) !== '') {
            $like = '%' . self::escapeLike(mb_strtolower(trim($options['q']))) . '%';
            list($a, $o, $e) = $this->overview->aliases();
            $sql .= " AND (LOWER(env.name) LIKE ? OR EXISTS (SELECT 1 FROM attributes $a"
                . " JOIN events $e ON $e.id = $a.event_id"
                . " JOIN objects $o ON $o.id = $a.object_id"
                . " WHERE $a.object_id = env.id AND $a.deleted = FALSE AND " . $acl['attribute']
                . ' AND ' . $this->valueSearchSql($like) . '))';
            $params[] = $like;
        }
        return [$sql, $params];
    }

    /**
     * Dated attributes of the given objects, by object id, earliest first.
     */
    private function children(array $acl, $basis, array $objectIds, $limit)
    {
        list($a, $o, $e) = $this->overview->aliases();
        $rows = $this->withValues($this->rows(
            "SELECT $a.id, $a.uuid, $a.event_id, $a.object_id,"
            . " $a.object_relation, $a.type, $a.category, $a.to_ids,"
            . " $a.value1_id, $a.value2_id,"
            . " $a.first_seen, $a.last_seen, $a.timestamp,"
            . ' ' . self::dateSql($basis, $a, 's') . ' AS s, ' . self::dateSql($basis, $a, 'e') . ' AS e'
            . " FROM attributes $a JOIN events $e ON $e.id = $a.event_id"
            . " JOIN objects $o ON $o.id = $a.object_id"
            . " WHERE $a.object_id IN (" . self::placeholders($objectIds) . ')'
            . " AND $a.event_id IN (" . $acl['events'] . ") AND $a.deleted = FALSE"
            . " AND $o.deleted = FALSE AND " . self::datedSql($basis, $a)
            . ' AND ' . $acl['attribute'] . ' AND ' . $acl['object']
            . " ORDER BY $a.object_id, s, $a.id LIMIT " . (int)$limit,
            array_map('intval', $objectIds)
        ));
        $children = [];
        foreach ($rows as $row) {
            $children[(int)$row['object_id']][] = self::attributeItem($row);
        }
        return $children;
    }

    public static function attributeItem(array $row)
    {
        $item = [
            'kind' => 'attribute',
            'id' => (int)$row['id'],
            'uuid' => $row['uuid'],
            'event_id' => (int)$row['event_id'],
            'label' => self::label($row['value1'], $row['value2'] ?? ''),
            'type' => $row['type'],
            'category' => $row['category'],
            'to_ids' => !empty($row['to_ids']),
            'first_seen' => self::micro($row['first_seen']),
            'last_seen' => self::micro($row['last_seen']),
            'timestamp' => self::secondsToMicro($row['timestamp'] ?? null),
            'start' => self::micro($row['s']),
            'end' => self::micro($row['e']),
        ];
        if (isset($row['object_relation'])) {
            $item['relation'] = $row['object_relation'];
        }
        return $item;
    }

    public static function objectItem(array $row)
    {
        return [
            'kind' => 'object',
            'id' => (int)$row['id'],
            'uuid' => $row['uuid'],
            'event_id' => (int)$row['event_id'],
            'label' => $row['name'],
            'category' => $row['category'],
            'first_seen' => self::micro($row['ofs']),
            'last_seen' => self::micro($row['ols']),
            'timestamp' => self::secondsToMicro($row['ots'] ?? null),
            'start' => self::micro($row['s']),
            'end' => self::micro($row['e']),
            'children_count' => (int)$row['dated_children'],
        ];
    }

    /**
     * An attribute's value as MISP shows it, a composite joined by a pipe,
     * cut to LABEL_MAX characters.
     */
    public static function label($value1, $value2)
    {
        $value = (string)$value1;
        if ((string)$value2 !== '') {
            $value .= '|' . $value2;
        }
        if (mb_strlen($value) > self::LABEL_MAX) {
            $value = mb_substr($value, 0, self::LABEL_MAX - 1) . '…';
        }
        return $value;
    }

    private static function micro($value)
    {
        return $value === null ? null : (int)$value;
    }

    private static function secondsToMicro($value)
    {
        return empty($value) ? null : (int)$value * 1000000;
    }

    /**
     * One row per visible object of the events, with its own dates (ofs, ols,
     * ots), the span of its visible dated attributes folded in (s, e) and how
     * many of those there are.
     */
    private function envelopeSql(array $acl, $basis)
    {
        list($a, $o, $e) = $this->overview->aliases();
        $category = $this->Object->getDataSource()->name('meta-category');
        $index = $this->Object->liveObjectIndex();
        $inner = "SELECT $o.id, $o.uuid, $o.event_id, $o.name,"
            . " $o.$category AS category, $o.first_seen AS ofs, $o.last_seen AS ols,"
            . " $o.timestamp AS ots,"
            . ' ' . self::dateSql($basis, $o, 's') . ' AS os, ' . self::dateSql($basis, $o, 'e') . ' AS oe,'
            . ' MIN(' . self::dateSql($basis, $a, 's') . ') AS amin,'
            . ' MAX(' . self::dateSql($basis, $a, 'e') . ') AS amax,'
            . " COUNT($a.id) AS dated_children"
            . " FROM objects $o" . ($index === null ? '' : ' FORCE INDEX (' . $index . ')')
            . " JOIN events $e ON $e.id = $o.event_id"
            . " LEFT JOIN attributes $a ON $a.object_id = $o.id AND $a.deleted = FALSE"
            . ' AND ' . self::datedSql($basis, $a) . ' AND ' . $acl['attribute']
            . " WHERE $o.event_id IN (" . $acl['events'] . ") AND $o.deleted = FALSE AND " . $acl['object']
            . " GROUP BY $o.id, $o.uuid, $o.event_id, $o.name, $o.$category,"
            . " $o.first_seen, $o.last_seen, $o.timestamp";
        return 'SELECT t.id, t.uuid, t.event_id, t.name, t.category, t.ofs, t.ols, t.ots, t.dated_children,'
            . ' LEAST(COALESCE(t.os, t.amin), COALESCE(t.amin, t.os)) AS s,'
            . ' GREATEST(COALESCE(t.oe, t.amax), COALESCE(t.amax, t.oe)) AS e'
            . ' FROM (' . $inner . ') t';
    }

    /**
     * FROM … WHERE for the events' loose attributes the user may read, pinned
     * to MispAttribute::looseAttributeIndex().
     */
    private function looseFrom(array $acl)
    {
        list($a, $o, $e) = $this->overview->aliases();
        $index = $this->Attribute->looseAttributeIndex();
        return "FROM attributes $a" . ($index === null ? '' : ' FORCE INDEX (' . $index . ')')
            . " JOIN events $e ON $e.id = $a.event_id"
            . " LEFT JOIN objects $o ON $o.id = $a.object_id"
            . " WHERE $a.event_id IN (" . $acl['events'] . ") AND $a.object_id = 0"
            . " AND $a.deleted = FALSE AND " . $acl['attribute'];
    }

    /**
     * The basis asked for, seen dates unless the timestamp is.
     */
    public static function basis(array $options)
    {
        return ($options['basis'] ?? null) === self::BASIS_TIMESTAMP ? self::BASIS_TIMESTAMP : self::BASIS_SEEN;
    }

    /**
     * The start (s) or end (e) of a row in microseconds: the earlier or later
     * seen date, whichever ends it has, or its timestamp, NULL when unset.
     */
    public static function dateSql($basis, $alias, $end)
    {
        if ($basis === self::BASIS_TIMESTAMP) {
            return "(NULLIF($alias.timestamp, 0) * 1000000)";
        }
        $first = "COALESCE($alias.first_seen, $alias.last_seen)";
        $last = "COALESCE($alias.last_seen, $alias.first_seen)";
        return ($end === 's' ? 'LEAST' : 'GREATEST') . "($first, $last)";
    }

    public static function datedSql($basis, $alias)
    {
        if ($basis === self::BASIS_TIMESTAMP) {
            return "$alias.timestamp > 0";
        }
        return "($alias.first_seen IS NOT NULL OR $alias.last_seen IS NOT NULL)";
    }

    private static function placeholders(array $values)
    {
        return implode(', ', array_fill(0, count($values), '?'));
    }

    private static function escapeLike($value)
    {
        return addcslashes($value, '%_\\');
    }

    /**
     * Rows read with value1_id / value2_id, given their value text cut as
     * the labels need it; the ids, which never leave the instance, dropped.
     */
    private function withValues(array $rows)
    {
        $ids = [];
        foreach ($rows as $row) {
            foreach (['value1_id', 'value2_id'] as $key) {
                if (!empty($row[$key])) {
                    $ids[(int)$row[$key]] = true;
                }
            }
        }
        $texts = empty($ids) ? [] : $this->dictionary()->fetchValues(array_keys($ids));
        $cut = function ($id) use ($texts) {
            return $id ? mb_substr((string)($texts[$id] ?? ''), 0, self::LABEL_MAX + 1) : '';
        };
        foreach ($rows as &$row) {
            $row['value1'] = $cut((int)($row['value1_id'] ?? 0));
            $row['value2'] = $cut((int)($row['value2_id'] ?? 0));
            unset($row['value1_id'], $row['value2_id']);
        }
        unset($row);
        return $rows;
    }

    /**
     * An attribute whose value1 or value2 matches $like, the dictionary read
     * per row: the event bounds the rows, so nothing reads it whole.
     */
    private function valueSearchSql($like)
    {
        $dictionary = $this->dictionary();
        return '(' . $dictionary->likeCondition('Attribute.value1_id', $like)->value
            . ' OR ' . $dictionary->likeCondition('Attribute.value2_id', $like)->value . ')';
    }

    private function dictionary()
    {
        return ClassRegistry::init('AttributeValue');
    }

    private function rows($sql, array $params = [])
    {
        $flat = [];
        foreach ($this->Attribute->query($sql, $params, false) as $row) {
            $r = [];
            foreach ($row as $part) {
                if (is_array($part)) {
                    $r += $part;
                }
            }
            $flat[] = $r;
        }
        return $flat;
    }
}
