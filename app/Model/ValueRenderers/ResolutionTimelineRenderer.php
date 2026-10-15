<?php

/**
 * What a name resolved to, and when.
 *
 * Three templates answer this and only one of them carries dates.
 * `passive-dns` has `time_first` and `time_last`; `domain-ip` has
 * `first-seen` and `last-seen` where whoever built it filled them in;
 * `dns-record` is a live lookup and has no dates at all.
 *
 * **An undated resolution is a set, not a timeline.** The obvious
 * reading — decline anything without dates, so the widget is always a
 * chart — throws away the one resolution answer every stock instance
 * has, because `dns` and `reversedns` are what an instance with no
 * passive-DNS subscription runs. So `matches()` accepts them and the
 * compact form draws the addresses as a set with a count: no
 * sparkline, no axis, and no pretence that an undated answer is a
 * history.
 *
 * `count` on a `passive-dns` object is how many times that resolution
 * was observed, and it is the weight behind a line rather than a
 * number of rows — a resolution seen forty thousand times and one
 * seen twice are both one row here.
 */
class ResolutionTimelineRenderer extends ValueRendererBase
{
    public $id = 'resolution-timeline';

    public $templates = array(
        'passive-dns',
        'domain-ip',
        'dns-record',
    );

    public $compact = 'Values/Renderers/resolution_timeline_compact';

    public $full = 'Values/Renderers/resolution_timeline_full';

    public $eventUse = self::EVENT_SET;

    /**
     * The `dns-record` relations that are a resolution, each with the
     * record type it is one of. `text` and `queried-domain` are not
     * resolutions — the first is prose and the second is the question.
     */
    const RECORDS = array(
        'a-record' => 'A',
        'aaaa-record' => 'AAAA',
        'cname-record' => 'CNAME',
        'mx-record' => 'MX',
        'ns-record' => 'NS',
        'ptr-record' => 'PTR',
        'soa-record' => 'SOA',
        'srv-record' => 'SRV',
        'spf-record' => 'SPF',
        'txt-record' => 'TXT',
    );

    public function __construct()
    {
        $this->description = __('What a name resolved to over time,'
            . ' or the set of what it resolves to now.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if (!empty($this->resolutionsOf($object))) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $rows = array();
        foreach ($objects as $object) {
            foreach ($this->resolutionsOf($object) as $row) {
                $rows[] = $row;
            }
        }
        /*
         * Deduplicated on the resolution itself and not on the row.
         * Two sources both knowing that a name pointed at an address
         * is one resolution two sources agree on; the window is the
         * union of what each of them saw, because each is reporting a
         * slice of the same history.
         */
        $merged = array();
        foreach ($rows as $row) {
            $key = $row['from'] . "\0" . $row['type'] . "\0"
                . $row['to'];
            if (!isset($merged[$key])) {
                $merged[$key] = $row;
                continue;
            }
            $held = $merged[$key];
            $merged[$key]['count'] = $held['count'] + $row['count'];
            $merged[$key]['first'] = $this->earlier(
                $held['first'],
                $row['first']
            );
            $merged[$key]['last'] = $this->later(
                $held['last'],
                $row['last']
            );
            if (!in_array($row['module'], $held['sources'], true)) {
                $merged[$key]['sources'][] = $row['module'];
            }
        }
        $merged = array_values($merged);
        $dated = 0;
        $first = null;
        $last = null;
        $months = array();
        foreach ($merged as $row) {
            if ($row['first'] === null && $row['last'] === null) {
                continue;
            }
            $dated++;
            $first = $this->earlier($first, $row['first']);
            $last = $this->later($last, $row['last']);
            /*
             * One tick per month a resolution was live in, not one per
             * observation: the strip is *how many distinct resolutions
             * were current then*, which is the shape an analyst reads
             * a hosting change out of. An observation count would draw
             * one spike wherever a sensor was busy.
             */
            foreach ($this->monthsBetween($row) as $month) {
                $months[$month] = ($months[$month] ?? 0) + 1;
            }
        }
        ksort($months);
        $months = $this->denseMonths($months);
        usort($merged, function ($a, $b) {
            return ($b['last'] ?? 0) - ($a['last'] ?? 0);
        });
        return array(
            'resolutions' => $merged,
            'distinct' => count($merged),
            'dated' => $dated > 0,
            'months' => $months,
            'periods' => $this->periods($merged, array_keys($months)),
            'first' => $first,
            'last' => $last,
            'sources' => $this->sources($objects),
        );
    }

    /**
     * Every resolution one object states, whatever template it is.
     *
     * @param array $object
     * @return array
     */
    private function resolutionsOf(array $object)
    {
        $name = $object['name'] ?? null;
        if ($name === 'passive-dns') {
            return $this->passiveDns($object);
        }
        if ($name === 'domain-ip') {
            return $this->domainIp($object);
        }
        if ($name === 'dns-record') {
            return $this->dnsRecord($object);
        }
        return array();
    }

    /**
     * @param array $object
     * @return array
     */
    private function passiveDns(array $object)
    {
        $from = $this->value($object, 'rrname');
        if ($from === null) {
            return array();
        }
        $type = $this->value($object, 'rrtype');
        $count = $this->number($this->value($object, 'count'));
        $out = array();
        /*
         * `rdata` repeats: one `passive-dns` object can carry every
         * address a name resolved to in one window.
         */
        foreach ($this->values($object, 'rdata') as $to) {
            $out[] = $this->row(
                $object,
                $from,
                $to,
                $type === null ? '' : $type,
                $this->stamp($this->value($object, 'time_first')),
                $this->stamp($this->value($object, 'time_last')),
                $count === null ? 1 : (int)$count
            );
        }
        return $out;
    }

    /**
     * @param array $object
     * @return array
     */
    private function domainIp(array $object)
    {
        $from = $this->firstValue($object, array('domain', 'hostname'));
        $to = $this->value($object, 'ip');
        if ($from === null || $to === null) {
            return array();
        }
        return array($this->row(
            $object,
            $from,
            $to,
            'A',
            $this->stamp($this->value($object, 'first-seen')),
            $this->stamp($this->value($object, 'last-seen')),
            1
        ));
    }

    /**
     * @param array $object
     * @return array
     */
    private function dnsRecord(array $object)
    {
        $from = $this->value($object, 'queried-domain');
        $out = array();
        foreach (self::RECORDS as $relation => $type) {
            foreach ($this->values($object, $relation) as $to) {
                $out[] = $this->row(
                    $object,
                    /*
                     * A live lookup need not say what was asked — a
                     * reverse lookup's object carries the PTR name and
                     * nothing else — and the page already knows the
                     * value it is about, so an empty left-hand side is
                     * a gap the template fills rather than a reason to
                     * drop the answer.
                     */
                    $from === null ? '' : $from,
                    $to,
                    $type,
                    null,
                    null,
                    1
                );
            }
        }
        return $out;
    }

    /**
     * @param array $object
     * @param string $from
     * @param string $to
     * @param string $type
     * @param int|null $first
     * @param int|null $last
     * @param int $count
     * @return array
     */
    private function row(array $object, $from, $to, $type, $first,
        $last, $count
    ) {
        return array(
            'from' => $from,
            'to' => $to,
            'type' => $type,
            'first' => $first,
            'last' => $last,
            'count' => max(1, $count),
            'module' => $object['module'] ?? null,
            'sources' => array($object['module'] ?? null),
        );
    }

    /**
     * The `Y-m` keys one resolution was live across, capped.
     *
     * A resolution whose window is fifteen years wide would otherwise
     * put 180 keys in the map on its own, and a sparkline of 180
     * points inside 190 pixels is a smear. The cap is on what one row
     * may contribute, not on the axis: a long-lived resolution counts
     * at each end and not through the middle, which is the honest
     * reading of *it was current then* when the middle was never
     * observed.
     *
     * @param array $row
     * @return array
     */
    private function monthsBetween(array $row)
    {
        $first = $row['first'] ?? $row['last'];
        $last = $row['last'] ?? $row['first'];
        if ($first === null || $last === null) {
            return array();
        }
        $months = array();
        $cursor = strtotime(date('Y-m-01', min($first, $last)));
        $end = strtotime(date('Y-m-01', max($first, $last)));
        while ($cursor !== false && $cursor <= $end
            && count($months) < 36
        ) {
            $months[] = date('Y-m', $cursor);
            $cursor = strtotime('+1 month', $cursor);
        }
        if ($cursor !== false && $cursor <= $end) {
            $months[] = date('Y-m', $end);
        }
        return $months;
    }

    /**
     * Every calendar month from the first to the last, zero where
     * nothing was current.
     *
     * A month with no resolution in it is a fact — a name that
     * resolved, stopped, and resolved again two years later is the
     * shape an analyst is looking for — and the counted months alone
     * cannot carry it: a strip drawn from them puts the two live
     * stretches side by side and reads as one continuous history.
     * Between two adjacent keys the gap is drawn rather than closed.
     *
     * @param array $months `YYYY-MM => count`, ascending
     * @return array The same, with the empty months filled in
     */
    private function denseMonths(array $months)
    {
        if (count($months) < 2) {
            return $months;
        }
        $keys = array_keys($months);
        $cursor = strtotime(reset($keys) . '-01');
        $end = strtotime(end($keys) . '-01');
        if ($cursor === false || $end === false) {
            return $months;
        }
        $dense = array();
        /*
         * The same bound `monthsBetween()` puts on one row, for the
         * same reason: a strip is read by its shape, and a span no
         * cell can draw a bar of is not a shape. Past it the counted
         * months stand on their own, which is what this drew before.
         */
        while ($cursor <= $end && count($dense) < 240) {
            $month = date('Y-m', $cursor);
            $dense[$month] = $months[$month] ?? 0;
            $cursor = strtotime('+1 month', $cursor);
        }
        return $cursor <= $end ? $months : $dense;
    }

    /**
     * The months the full form brushes over, each counting the
     * resolutions whose window overlaps it.
     *
     * Not `months`: that one stops counting a long-lived resolution
     * after three years, and the brush filters by overlap, so a bar
     * drawn from it could sit empty over rows the filter keeps.
     *
     * @param array $rows Merged resolutions
     * @param array $keys `Y-m` keys, ascending
     * @return array `[{from, to, label, count}]`, `Y-m-d` bounds
     */
    private function periods(array $rows, array $keys)
    {
        $periods = array();
        foreach ($keys as $key) {
            $start = strtotime($key . '-01');
            if ($start === false) {
                continue;
            }
            $end = strtotime('+1 month', $start) - 1;
            $count = 0;
            foreach ($rows as $row) {
                $first = $row['first'] ?? $row['last'];
                $last = $row['last'] ?? $row['first'];
                if ($first !== null && $first <= $end
                    && $last >= $start
                ) {
                    $count++;
                }
            }
            $periods[] = array(
                'from' => date('Y-m-d', $start),
                'to' => date('Y-m-d', $end),
                'label' => $key,
                'count' => $count,
            );
        }
        return $periods;
    }

    /**
     * @param int|null $a
     * @param int|null $b
     * @return int|null
     */
    private function earlier($a, $b)
    {
        if ($a === null) {
            return $b;
        }
        if ($b === null) {
            return $a;
        }
        return min($a, $b);
    }

    /**
     * @param int|null $a
     * @param int|null $b
     * @return int|null
     */
    private function later($a, $b)
    {
        if ($a === null) {
            return $b;
        }
        if ($b === null) {
            return $a;
        }
        return max($a, $b);
    }
}
