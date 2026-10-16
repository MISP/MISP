<?php

/**
 * The bucket series behind every brushable activity chart on the Value
 * Profile page: the Sightings navigator, the Timeline spine and the
 * History months.
 *
 * All three draw one bar per bucket over a span. The bucket unit is
 * what they actually disagree about, so it is the parameter here
 * rather than a literal in each.
 *
 * Why the unit is given and not derived from the span: a bar means
 * something different in each chart. A Sightings bar counts reports,
 * and a report has a timestamp, so a day is an honest grain. A
 * Timeline bar is a density over sources MISP cannot all date to the
 * day, so a month is the finest claim it can make. Deriving the unit
 * from the span alone would let the Timeline draw daily bars it has no
 * right to — so a caller whose data supports it opts in to the
 * span-to-unit rule, and one whose data does not names its unit and
 * keeps it however wide the span gets.
 */
class ValueIntelligenceBuckets
{
    const DAY = 'day';
    const WEEK = 'week';
    const MONTH = 'month';

    /**
     * Which end of the span the buckets are aligned to. Only `week`
     * reads it: a day is a day whichever way you count, and a month is
     * a calendar month.
     *
     * The two shipped callers genuinely disagree. The Sightings ranges
     * are `last 90 days` and `last 365 days`, so their last bucket has
     * to end exactly at today or the range does not hold what it says;
     * the History chart runs from the log's first day, so its first
     * bucket has to start there.
     */
    const START = 'start';
    const END = 'end';

    /**
     * The span-to-unit rule: daily columns only make sense while there
     * are fewer of them than the chart has pixels, and past a quarter
     * the bucket is a week.
     *
     * First match wins; a `days` of null is the catch-all.
     */
    public static $spanRule = array(
        array('days' => 90, 'unit' => self::DAY),
        array('days' => null, 'unit' => self::WEEK),
    );

    /**
     * The unit a span of this many days should be drawn at, for a
     * caller whose data supports choosing.
     *
     * @param int|null $days null for an unbounded span
     * @param array|null $rule Defaults to `$spanRule`
     * @return string
     */
    public static function unitForSpan($days, array $rule = null)
    {
        $rule = $rule === null ? self::$spanRule : $rule;
        foreach ($rule as $step) {
            if ($step['days'] === null) {
                return $step['unit'];
            }
            // An unbounded span matches no bounded threshold: it is
            // wider than every one of them by construction.
            if ($days !== null && $days <= $step['days']) {
                return $step['unit'];
            }
        }
        return self::WEEK;
    }

    /**
     * The buckets covering `$from`..`$to` inclusive, at `$unit`.
     *
     * The last bucket is clipped to `$to` rather than run to the end of
     * its own unit: there is no data after the span's end, and a bar
     * drawn over days that have not happened invites the reader to
     * read a dip in it.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @param string $unit One of DAY, WEEK, MONTH
     * @param string $anchor START or END; `week` only
     * @return array List of `key`, `label`, `title`, `from`, `to`
     */
    public static function series($from, $to, $unit, $anchor = self::START)
    {
        if ($unit === self::MONTH) {
            $spans = self::monthSpans($from, $to);
        } elseif ($anchor === self::END) {
            $spans = self::stepSpansFromEnd($from, $to, self::size($unit));
        } else {
            $spans = self::stepSpansFromStart($from, $to, self::size($unit));
        }
        $buckets = array();
        foreach ($spans as $span) {
            $buckets[] = self::describe($span, $unit);
        }
        return $buckets;
    }

    /**
     * A `Y-m-d` to bucket-index map covering the whole series, so a
     * caller tallying rows into it does a lookup rather than a scan.
     *
     * A day the series does not cover is simply absent, which is how a
     * caller tells that a row falls outside its chart.
     *
     * @param array $buckets From `series()`
     * @return array
     */
    public static function locate(array $buckets)
    {
        $utc = new DateTimeZone('UTC');
        $map = array();
        foreach ($buckets as $index => $bucket) {
            $day = new DateTimeImmutable(
                $bucket['from'] . ' 00:00:00',
                $utc
            );
            $stop = $bucket['to'];
            while ($day->format('Y-m-d') <= $stop) {
                $map[$day->format('Y-m-d')] = $index;
                $day = $day->modify('+1 day');
            }
        }
        return $map;
    }

    /**
     * Everything a chart the browser re-aggregates needs: one bucket
     * series per unit the caller's rule permits, over the same span.
     *
     * This is affordable because a bar is a label and a count, so the
     * value's whole span at every grain its data supports is tens of
     * kilobytes. The browser can therefore hold all of it and pick a
     * grain per zoom level without going back to the server.
     *
     * **This class ships every string the browser cannot already
     * derive, and the browser computes every number.** A grain is two
     * arrays of labels and one array of start offsets, not a list of
     * bucket objects, and the split is the reason: `j M` and `F Y` are
     * decisions, so duplicating them in JavaScript would be a second
     * formatter to keep in step with `describe()`; a bucket's start
     * date and its end date are arithmetic over the span, so shipping
     * them as text costs bytes and settles nothing. Sent as objects,
     * most of the payload would be field names and `Y-m-d` dates
     * repeated five times a bar.
     *
     * **The day grain is the one exception, and it ships no strings at
     * all.** Its bucket `i` is the day `$from + i` and nothing else can
     * be, so its label is `j M` of a date the browser has already
     * worked out — the one case where the second formatter costs no
     * second decision. It is also the expensive one: the span cap is
     * 1,095 days, and a label and a title for each of them would
     * dominate the payload, several times the week grain over the same
     * span. `label` and `title` are `null` there,
     * on the same convention `starts` already uses, and `zoomDayLabel`
     * in `value-intelligence.js` is the other half of it.
     *
     * `starts` is a day offset from `$from`, and the month grain's
     * first one is normally negative: a month bucket is a whole
     * calendar month at the low end, because a bar labelled `Jun` that
     * begins on the 14th is not June. `null` means the offsets are the
     * identity, which is what `day` always is.
     *
     * A bucket's end is the next bucket's start less one, and the last
     * one ends with the span. So the buckets tile it exactly, which is
     * what lets the browser sum a slice per bar and stop.
     *
     * The grains carry no totals. A count belongs to what is being
     * counted and the caller owns that.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @param array $rule Span-to-unit rule, as `unitForSpan()` takes
     * @param string $anchor START or END; `week` only
     * @return array `from`, `to`, `days`, `rule`, `grains`
     */
    public static function plan($from, $to, array $rule,
        $anchor = self::START)
    {
        $grains = array();
        foreach ($rule as $step) {
            $unit = $step['unit'];
            if (isset($grains[$unit])) {
                continue;
            }
            $series = self::series($from, $to, $unit, $anchor);
            $day = $unit === self::DAY;
            $starts = array();
            $labels = array();
            $titles = array();
            foreach ($series as $bucket) {
                $starts[] = self::diff($from, $bucket['from']);
                $labels[] = $bucket['label'];
                $titles[] = $bucket['title'];
            }
            $grains[$unit] = array(
                'starts' => $day ? null : $starts,
                'label' => $day ? null : $labels,
                'title' => $day ? null : $titles,
                // Only the day grain needs to say how many buckets it
                // has, since it is the only one whose arrays are gone.
                // `plan.days` is the same number, but a grain that
                // cannot be counted from its own fields would make the
                // browser special-case the unit to find its length.
                'count' => count($series),
            );
        }
        return array(
            'from' => $from,
            'to' => $to,
            'days' => self::diff($from, $to) + 1,
            'rule' => $rule,
            'grains' => $grains,
        );
    }

    /**
     * The dense per-day tally the browser sums into whichever grain it
     * draws, one slot per day of the span.
     *
     * Dense rather than a map of only the days that carry something:
     * sparse wins on a quiet value by tens of bytes and loses on a busy
     * one by kilobytes. A dense array is bounded at about a kilobyte
     * over a fourteen-month span and needs no decode.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @param array $days `Y-m-d` => count, for the days that have one
     * @return array
     */
    public static function tally($from, $to, array $days)
    {
        $span = self::diff($from, $to) + 1;
        $counts = array_fill(0, max(0, $span), 0);
        foreach ($days as $day => $count) {
            $offset = self::diff($from, $day);
            if ($offset >= 0 && $offset < $span) {
                $counts[$offset] += $count;
            }
        }
        return $counts;
    }

    /**
     * The same tally as `tally()`, keyed by the offsets that carry
     * something and leaving out the ones that do not.
     *
     * Which encoding is smaller depends entirely on the series. One
     * series counting every audit entry a value has is dense — most
     * days carry one on a busy value — and a sparse map of it costs
     * several times what a dense array does. A series counting *one
     * organisation's* sighting reports is the opposite: a few hundred
     * reports spread over a couple of dozen organisations leaves each
     * one touching a handful of days, and a dense array per
     * organisation is a row of mostly zero.
     *
     * So the choice is the caller's and it is a statement about what
     * the series is, not a size heuristic: History's one series is
     * dense, and the Sightings navigator's per-organisation ones are
     * sparse. The browser inflates these to dense once when the panel
     * lands, so only the wire format differs.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @param array $days `Y-m-d` => count, for the days that have one
     * @return array Offset from `$from` => count
     */
    public static function sparse($from, $to, array $days)
    {
        $span = self::diff($from, $to) + 1;
        $at = array();
        foreach ($days as $day => $count) {
            $offset = self::diff($from, $day);
            if ($offset >= 0 && $offset < $span && $count !== 0) {
                $at[$offset] = ($at[$offset] ?? 0) + $count;
            }
        }
        ksort($at);
        return $at;
    }

    /**
     * What one drawn column stands for, by unit.
     *
     * A keyed list rather than a ternary, so that adding a unit is
     * adding a line here and not finding every `if` that assumed there
     * were two. All of them rather than the drawn one, because the
     * drawn one is a fact about how far the reader has zoomed and the
     * browser is what knows it.
     *
     * @return array
     */
    public static function columnLabels()
    {
        return array(
            self::DAY => __('one column per day'),
            self::WEEK => __('one column per week'),
            self::MONTH => __('one column per month'),
        );
    }

    /**
     * @param string $unit
     * @return int Days per bucket
     */
    private static function size($unit)
    {
        return $unit === self::WEEK ? 7 : 1;
    }

    /**
     * Calendar months, whole at the low end and clipped at the high
     * one. A month bucket starting mid-month would be a bar labelled
     * `Mar` that is not March.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @return array
     */
    private static function monthSpans($from, $to)
    {
        $utc = new DateTimeZone('UTC');
        $cursor = new DateTimeImmutable(
            substr($from, 0, 7) . '-01 00:00:00',
            $utc
        );
        $last = substr($to, 0, 7);
        $spans = array();
        while ($cursor->format('Y-m') <= $last) {
            $stop = $cursor->modify('last day of this month')
                ->format('Y-m-d');
            $spans[] = array(
                'from' => $cursor->format('Y-m-d'),
                'to' => min($stop, $to),
            );
            $cursor = $cursor->modify('first day of next month');
        }
        return $spans;
    }

    /**
     * Fixed-width buckets laid forwards from `$from`, so the first one
     * is whole and the last is clipped.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @param int $step Days
     * @return array
     */
    private static function stepSpansFromStart($from, $to, $step)
    {
        $spans = array();
        $cursor = $from;
        while (self::diff($cursor, $to) >= 0) {
            $stop = self::shift($cursor, $step - 1);
            if (self::diff($stop, $to) < 0) {
                $stop = $to;
            }
            $spans[] = array('from' => $cursor, 'to' => $stop);
            $cursor = self::shift($stop, 1);
        }
        return $spans;
    }

    /**
     * Fixed-width buckets laid backwards from `$to`, so the last one is
     * whole and the first is clipped.
     *
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @param int $step Days
     * @return array
     */
    private static function stepSpansFromEnd($from, $to, $step)
    {
        $spans = array();
        $cursor = $to;
        while (self::diff($from, $cursor) >= 0) {
            $start = self::shift($cursor, -($step - 1));
            if (self::diff($from, $start) < 0) {
                $start = $from;
            }
            array_unshift($spans, array(
                'from' => $start,
                'to' => $cursor,
            ));
            $cursor = self::shift($start, -1);
        }
        return $spans;
    }

    /**
     * The key, the label and the tooltip title for one bucket.
     *
     * All three are formatted off the bucket's `to`. For a month that
     * is the same month as its `from`, and for a day it is the same
     * day; for a week it is the end of the week, which is what the
     * Sightings navigator labels its columns with.
     *
     * @param array $span `from` and `to`
     * @param string $unit
     * @return array
     */
    private static function describe(array $span, $unit)
    {
        $utc = new DateTimeZone('UTC');
        $end = new DateTimeImmutable($span['to'] . ' 00:00:00', $utc);
        if ($unit === self::MONTH) {
            return array(
                'key' => $end->format('Y-m'),
                'label' => $end->format('M'),
                'title' => $end->format('F Y'),
                'from' => $span['from'],
                'to' => $span['to'],
            );
        }
        $start = new DateTimeImmutable($span['from'] . ' 00:00:00', $utc);
        $title = $span['from'] === $span['to']
            ? $end->format('j M Y')
            : $start->format('j M') . ' – ' . $end->format('j M Y');
        return array(
            'key' => $span['from'],
            'label' => $end->format('j M'),
            'title' => $title,
            'from' => $span['from'],
            'to' => $span['to'],
        );
    }

    /**
     * @param string $from `Y-m-d`
     * @param string $to `Y-m-d`
     * @return int
     */
    private static function diff($from, $to)
    {
        $utc = new DateTimeZone('UTC');
        $a = new DateTimeImmutable($from . ' 00:00:00', $utc);
        $b = new DateTimeImmutable($to . ' 00:00:00', $utc);
        return (int)$a->diff($b)->format('%r%a');
    }

    /**
     * @param string $date `Y-m-d`
     * @param int $days
     * @return string
     */
    private static function shift($date, $days)
    {
        $utc = new DateTimeZone('UTC');
        $d = new DateTimeImmutable($date . ' 00:00:00', $utc);
        return $d->modify(($days >= 0 ? '+' : '') . $days . ' days')
            ->format('Y-m-d');
    }
}
