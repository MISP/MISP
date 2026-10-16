<?php
App::uses('CakeTime', 'Utility');

/**
 * The view-model of one rail card on a detail page.
 *
 * A card is a plain array: an envelope shared by every shape, plus the
 * body of its shape. Producers build cards with the static constructors
 * here, which validate the body so a template never has to guess at a
 * missing key.
 *
 * Envelope:
 *   shape  string       one of SHAPES
 *   id     string       stable, unique on the page
 *   title  string
 *   icon   string       full class attribute of the header glyph
 *   link   array|null   ['label', 'href'] — a header link, e.g. to a tab
 *   empty  string|null  what the body says when it has nothing to show
 *   note   string|null  a per-instance remark (a setting that is off)
 *   lazy   bool         the page loads the card after first paint
 *
 * Shape bodies are documented on each constructor.
 */
class RailCard
{
    const SHAPES = ['inventory', 'activity', 'list', 'usage', 'status', 'facts'];

    const TONES = [null, 'ok', 'info', 'warn', 'danger', 'muted'];

    /** Entities with a theme colour, used as --bs-<name> */
    const COLOURS = [
        null, 'event', 'object', 'attribute', 'tag', 'galaxy', 'report',
        'sighting', 'correlation', 'category', 'type', 'analystData', 'enrichment',
        'valueIntelligence', 'analystGraph',
    ];

    /**
     * Every group counts in the total's unit. `partition` on the card says
     * the groups add up to the total; on a group, that its facets (with
     * `more` standing for the facets left out) add up to the group's count.
     *
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param array $total ['count' => int, 'label' => string]
     * @param array $groups each ['key', 'label', 'icon'?, 'color'?, 'count',
     *                     'partition'?, 'filter'?, 'facets' => [['label',
     *                     'count'|null, 'filter'?, 'href'?, 'tone'?]],
     *                     'more' => int]
     * @param bool $partition
     * @param array $options envelope keys
     * @return array
     */
    public static function inventory($id, $title, $icon, array $total, array $groups, $partition, array $options = [])
    {
        self::requireKeys($total, ['count', 'label'], "$id.total");
        $sum = 0;
        foreach ($groups as $i => $group) {
            self::requireKeys($group, ['key', 'label', 'count'], "$id.groups.$i");
            $groups[$i] += [
                'icon' => null, 'color' => null, 'partition' => false,
                'filter' => null, 'facets' => [], 'more' => 0,
            ];
            if (!in_array($groups[$i]['color'], self::COLOURS, true)) {
                throw new InvalidArgumentException("$id.groups.$i: invalid color '{$groups[$i]['color']}'");
            }
            $sum += $groups[$i]['count'];
            foreach ($groups[$i]['facets'] as $j => $facet) {
                self::requireKeys($facet, ['label'], "$id.groups.$i.facets.$j");
                $groups[$i]['facets'][$j] = self::tone($facet + [
                    'count' => null, 'filter' => null, 'href' => null, 'tone' => null,
                ], "$id.groups.$i.facets.$j");
            }
            $shown = array_sum(array_column($groups[$i]['facets'], 'count'));
            if ($groups[$i]['partition'] && ($shown > $groups[$i]['count']
                || (!$groups[$i]['more'] && $shown !== $groups[$i]['count']))) {
                throw new InvalidArgumentException("$id.groups.$i: facets do not partition the group");
            }
        }
        if ($partition && $sum !== $total['count']) {
            throw new InvalidArgumentException("$id: groups do not partition the total");
        }
        return self::envelope('inventory', $id, $title, $icon, $options) + [
            'total' => $total,
            'partition' => (bool)$partition,
            'groups' => array_values($groups),
        ];
    }

    /**
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param string $bucket 'day' or 'month'
     * @param array $series oldest first, contiguous, zero-filled:
     *                      [['start' => 'Y-m-d', 'count' => int]]
     * @param array $total ['count' => int, 'label' => string]
     * @param array|null $last ['ts' => int, 'label' => string, 'ago' => string]
     * @param array $stats [['label', 'value']]
     * @param array $options envelope keys
     * @return array
     */
    public static function activity($id, $title, $icon, $bucket, array $series, array $total, $last = null, array $stats = [], array $options = [])
    {
        if (!in_array($bucket, ['day', 'month'], true)) {
            throw new InvalidArgumentException("$id: bucket must be day or month");
        }
        foreach ($series as $i => $point) {
            self::requireKeys($point, ['start', 'count'], "$id.series.$i");
        }
        self::requireKeys($total, ['count', 'label'], "$id.total");
        foreach ($stats as $i => $stat) {
            self::requireKeys($stat, ['label', 'value'], "$id.stats.$i");
        }
        return self::envelope('activity', $id, $title, $icon, $options) + [
            'bucket' => $bucket,
            'series' => array_values($series),
            'total' => $total,
            'last' => $last,
            'stats' => $stats,
        ];
    }

    /**
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param array $rows each ['label', 'href'?, 'icon'?, 'meta' => [string],
     *                   'count' => int|null, 'share' => float|null (0..1),
     *                   'badge' => ['label', 'tone']|null, 'tone'?,
     *                   'action' => ['label', 'href', 'method', 'confirm']|null]
     * @param array|null $more ['label', 'href'|null]
     * @param array $options envelope keys
     * @return array
     */
    public static function rows($id, $title, $icon, array $rows, $more = null, array $options = [])
    {
        foreach ($rows as $i => $row) {
            self::requireKeys($row, ['label'], "$id.rows.$i");
            $row += [
                'href' => null, 'icon' => null, 'meta' => [], 'count' => null,
                'share' => null, 'badge' => null, 'tone' => null, 'action' => null,
            ];
            if ($row['badge'] !== null) {
                self::requireKeys($row['badge'], ['label'], "$id.rows.$i.badge");
                $row['badge'] = self::tone($row['badge'] + ['tone' => null], "$id.rows.$i.badge");
            }
            if ($row['action'] !== null) {
                self::requireKeys($row['action'], ['label', 'href'], "$id.rows.$i.action");
                $row['action'] += ['method' => 'get', 'confirm' => null];
            }
            $rows[$i] = self::tone($row, "$id.rows.$i");
        }
        if ($more !== null) {
            self::requireKeys($more, ['label'], "$id.more");
            $more += ['href' => null];
        }
        return self::envelope('list', $id, $title, $icon, $options) + [
            'rows' => array_values($rows),
            'more' => $more,
        ];
    }

    /**
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param array $headline ['count' => int, 'label' => string, 'context' => string|null]
     * @param array $split [['label', 'count', 'tone'?]]
     * @param array|null $last ['ts' => int, 'label' => string, 'ago' => string]
     * @param array $options envelope keys
     * @return array
     */
    public static function usage($id, $title, $icon, array $headline, array $split, $last = null, array $options = [])
    {
        self::requireKeys($headline, ['count', 'label'], "$id.headline");
        foreach ($split as $i => $part) {
            self::requireKeys($part, ['label', 'count'], "$id.split.$i");
            $split[$i] = self::tone($part + ['tone' => null], "$id.split.$i");
        }
        return self::envelope('usage', $id, $title, $icon, $options) + [
            'headline' => $headline + ['context' => null],
            'split' => array_values($split),
            'last' => $last,
        ];
    }

    /**
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param string $state a tone: how the record is doing as a whole
     * @param string $headline one sentence stating that state
     * @param array $items [['label', 'value', 'tone'?]]
     * @param array|null $action ['label', 'href', 'method']
     * @param array $options envelope keys
     * @return array
     */
    public static function status($id, $title, $icon, $state, $headline, array $items, $action = null, array $options = [])
    {
        foreach ($items as $i => $item) {
            self::requireKeys($item, ['label', 'value'], "$id.items.$i");
            $items[$i] = self::tone($item + ['tone' => null], "$id.items.$i");
        }
        $card = self::envelope('status', $id, $title, $icon, $options) + [
            'state' => $state,
            'headline' => $headline,
            'items' => array_values($items),
            'action' => $action,
        ];
        return self::tone($card, $id, 'state');
    }

    /**
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param array $rows [['label', 'values' => [['text', 'href'?]], 'more' => int]]
     * @param array $options envelope keys
     * @return array
     */
    public static function facts($id, $title, $icon, array $rows, array $options = [])
    {
        foreach ($rows as $i => $row) {
            self::requireKeys($row, ['label', 'values'], "$id.rows.$i");
            foreach ($row['values'] as $j => $value) {
                self::requireKeys($value, ['text'], "$id.rows.$i.values.$j");
                $rows[$i]['values'][$j] += ['href' => null];
            }
            $rows[$i] += ['more' => 0];
        }
        return self::envelope('facts', $id, $title, $icon, $options) + [
            'rows' => array_values($rows),
        ];
    }

    /**
     * A lazy card before it is computed: enough for its placeholder, and the
     * app-relative url the page fetches the rendered card from.
     *
     * @param string $shape
     * @param string $id
     * @param string $title
     * @param string $icon
     * @param string $url
     * @return array
     */
    public static function slot($shape, $id, $title, $icon, $url)
    {
        if (!in_array($shape, self::SHAPES, true)) {
            throw new InvalidArgumentException("$id: invalid shape '$shape'");
        }
        return [
            'shape' => $shape,
            'id' => $id,
            'title' => $title,
            'icon' => $icon,
            'url' => $url,
            'lazy' => true,
        ];
    }

    /**
     * @param array $cards cards and slots
     * @return array the same, keyed by card id
     */
    public static function byId(array $cards)
    {
        return array_column($cards, null, 'id');
    }

    /**
     * @param int|null $ts
     * @param string $label
     * @return array|null
     */
    public static function last($ts, $label)
    {
        if (empty($ts)) {
            return null;
        }
        return [
            'ts' => (int)$ts,
            'label' => $label,
            'ago' => self::ago((int)$ts),
        ];
    }

    /**
     * "3 hours ago", "in 5 days": the largest unit only.
     *
     * @param int $ts
     * @return string
     */
    public static function ago($ts)
    {
        $units = ['second', 'minute', 'hour', 'day', 'week', 'month', 'year'];
        return CakeTime::timeAgoInWords((int)$ts, [
            'end' => '+100 years',
            'accuracy' => array_combine($units, $units),
        ]);
    }

    /**
     * Count the rows of a find, reading at most $cap of them.
     *
     * @param Model $model
     * @param array $query find options; fields and limit are replaced
     * @param int $cap
     * @return array [int $count, bool $capped]
     */
    public static function countUpTo(Model $model, array $query, $cap)
    {
        $ids = $model->find('column', [
            'fields' => [$model->alias . '.id'],
            'limit' => $cap,
        ] + $query);
        $count = count($ids);
        return [$count, $count >= $cap];
    }

    /**
     * Zero-filled buckets from $from to today, oldest first.
     *
     * @param array $counts 'Y-m-d' (day) or 'Y-m' (month) => int
     * @param string $bucket
     * @param int $periods
     * @return array
     */
    public static function series(array $counts, $bucket, $periods)
    {
        $series = [];
        $cursor = new DateTime('today');
        if ($bucket === 'month') {
            $cursor->modify('first day of this month');
        }
        $step = $bucket === 'month' ? '-1 month' : '-1 day';
        for ($i = 0; $i < $periods; $i++) {
            $key = $cursor->format($bucket === 'month' ? 'Y-m' : 'Y-m-d');
            $series[] = [
                'start' => $cursor->format('Y-m-d'),
                'count' => (int)($counts[$key] ?? 0),
            ];
            $cursor->modify($step);
        }
        return array_reverse($series);
    }

    private static function envelope($shape, $id, $title, $icon, array $options)
    {
        $unknown = array_diff(array_keys($options), ['link', 'empty', 'note', 'lazy']);
        if (!empty($unknown)) {
            throw new InvalidArgumentException("$id: unknown envelope keys " . implode(', ', $unknown));
        }
        if (!empty($options['link'])) {
            self::requireKeys($options['link'], ['label', 'href'], "$id.link");
        }
        return [
            'shape' => $shape,
            'id' => $id,
            'title' => $title,
            'icon' => $icon,
            'link' => $options['link'] ?? null,
            'empty' => $options['empty'] ?? null,
            'note' => $options['note'] ?? null,
            'lazy' => !empty($options['lazy']),
        ];
    }

    private static function requireKeys(array $array, array $keys, $path)
    {
        foreach ($keys as $key) {
            if (!array_key_exists($key, $array)) {
                throw new InvalidArgumentException("$path: missing '$key'");
            }
        }
    }

    private static function tone(array $array, $path, $key = 'tone')
    {
        if (!in_array($array[$key] ?? null, self::TONES, true)) {
            throw new InvalidArgumentException("$path: invalid $key '{$array[$key]}'");
        }
        return $array;
    }
}
