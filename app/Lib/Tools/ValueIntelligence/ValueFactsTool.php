<?php

/**
 * The six-cell strip under the value, built from one aggregate.
 *
 * The first thing on the page and the last thing converted: the strip
 * is the page frame's, the frame is fetched synchronously, and a query
 * added here is a query on the critical path of every page load. So it
 * is built from `Value::occurrenceSummaryFor` and the type group-by the
 * banner chips already pay for, and nothing else — every cell it cannot
 * fill from those two is absent rather than bought.
 *
 * **No `$user`**: what reaches this is already the viewer's, and a
 * tool that could re-scope its answer is a tool that can get the scope
 * wrong in a second place.
 *
 * **Every cell jumps to the tab holding the rows behind it**, so no
 * figure on the strip is a dead end — which is also why the tab ids are
 * asserted against the registry rather than copied by hand: a tab id
 * can be renamed, and a hand-copied link goes on naming a tab that no
 * longer exists.
 */
class ValueFactsTool
{
    /** The tab ids this strip links to, as `Values/view.ctp` registers them. */
    const TAB_TIMELINE = 'timeline';
    const TAB_OCCURRENCES = 'occurrences';
    const TAB_ASSESSMENT = 'assessment';
    const TAB_SIGHTINGS = 'sightings';

    /**
     * The strip, as `value_fact_strip` reads it.
     *
     * **Six cells, and the sixth is the hard one.** A sighting count
     * has to be the viewer's, `Sightings_policy` hides whole reports,
     * and getting the viewer's number by running the policy over
     * fetched rows would cost the Sightings panel's own thirteen
     * queries, on every page load of every value.
     *
     * `Value::sightingCountsFor` expresses the policy as a predicate
     * over the joined rows rather than over an id set, so the count is
     * one indexed aggregate and nothing has to be materialised. It is
     * verified against
     * `Sighting::listSightings` — MISP's own answer — under all four
     * policies and three readers, which is the bar an access rule
     * rewritten as SQL has to clear.
     *
     * @param array $summary `Value::occurrenceSummaryFor`
     * @param array $types `Value::typesFor`
     * @param array $sightings `Value::sightingCountsFor`
     * @param int|null $now Override for testing
     * @param array|null $proposed Pending proposals adding the value,
     *     `count`, `oldest`, `newest`; given only when it has no
     *     occurrence
     * @return array
     */
    public static function strip(array $summary, array $types,
        array $sightings, $now = null, ?array $proposed = null
    ) {
        $now = $now === null ? time() : $now;
        $occurrencesSub = empty($types)
            ? null
            : sprintf(
                __n('%s type', '%s types', count($types)),
                count($types)
            );
        if ($proposed !== null) {
            $occurrencesSub = sprintf(
                __n('%s proposed', '%s proposed', $proposed['count']),
                number_format($proposed['count'])
            );
        }
        return array(
            $proposed === null
                ? self::dateFact(
                    __('First seen'),
                    $summary['oldest'],
                    $summary['dated_from'],
                    $now
                )
                : self::proposedFact(__('First proposed'), $proposed['oldest']),
            $proposed === null
                ? self::dateFact(
                    __('Last seen'),
                    $summary['newest'],
                    $summary['dated_at'],
                    $now
                )
                : self::proposedFact(__('Last proposed'), $proposed['newest']),
            array(
                'label' => __('Occurrences'),
                'value' => number_format($summary['occurrences']),
                'sub' => $occurrencesSub,
                'tab' => self::TAB_OCCURRENCES,
            ),
            array(
                'label' => __('Events'),
                'value' => number_format($summary['events']),
                'sub' => $summary['events'] === 0
                    ? null
                    : sprintf(
                        __('%s published'),
                        number_format($summary['published'])
                    ),
                'tab' => self::TAB_OCCURRENCES,
            ),
            array(
                'label' => __('Organisations'),
                'value' => number_format($summary['orgs']),
                'sub' => null,
                'tab' => self::TAB_ASSESSMENT,
            ),
            array(
                'label' => __('Sightings'),
                /*
                 * `sighting`, not `total`: the Overview's own sightings
                 * card breaks the three kinds of row apart and heads
                 * the first *47 Sightings*, so a cell printing the
                 * combined 53 under the same word would contradict the
                 * card it sits above. `Value::sightingCountsFor` has
                 * the arithmetic.
                 */
                'value' => number_format($sightings['sighting']),
                /*
                 * Only where there are any. *0 false positives* on the
                 * majority of values is a line that says nothing and
                 * takes the space of one that would.
                 */
                'sub' => empty($sightings['fp'])
                    ? null
                    : sprintf(
                        __n(
                            '%s false positive',
                            '%s false positives',
                            $sightings['fp']
                        ),
                        number_format($sightings['fp'])
                    ),
                'tab' => self::TAB_SIGHTINGS,
            ),
        );
    }

    /**
     * One of the two date cells, and whether its date is a date at all.
     *
     * `Value::observedFrom()`/`observedAt()` end in `Attribute.timestamp`, so
     * the aggregate always returns *something* — and on the many
     * attributes that declare no observation date that something is a
     * row write. A row write is when somebody last touched the record,
     * which an edit, a tag, a sync update or a delete all bump, so
     * printing it under *First seen* states an edit as a sighting.
     *
     * The cell prints it anyway, because it is the best available
     * answer and the alternative is a strip with two empty cells on
     * most values. What it does not do is print it **as if it were
     * declared**: with no occurrence declaring the column that leads
     * this chain, the sub-line says the date is a record date rather
     * than an observation, and the reader can discount it.
     *
     * @param string $label
     * @param int|null $stamp
     * @param int $declared Occurrences declaring the leading column
     * @param int $now
     * @return array
     */
    private static function proposedFact($label, $stamp)
    {
        return array(
            'label' => $label,
            'value' => date('Y-m-d', $stamp),
            'sub' => __('a proposal, not yet an occurrence'),
            'tab' => self::TAB_OCCURRENCES,
        );
    }

    private static function dateFact($label, $stamp, $declared, $now)
    {
        if ($stamp === null) {
            return array(
                'label' => $label,
                'value' => __('Not recorded'),
                'sub' => __('no occurrence you can see'),
                'tab' => null,
            );
        }
        return array(
            'label' => $label,
            'value' => date('Y-m-d', $stamp),
            'sub' => $declared > 0
                ? self::agePhrase($stamp, $now)
                : __('record date, not observed'),
            'tab' => self::TAB_TIMELINE,
        );
    }

    /**
     * How long ago, over the whole range a value's history can span.
     *
     * `ValueStatsTool::agoPhrase` stops at 31 days and prints the date
     * beyond that, which is right for a panel sub-line sitting beside
     * the date it qualifies and wrong here, where the cell above
     * already prints the date and the sub is the only thing saying how
     * long ago that was.
     *
     * Months are 30 days and years are 365. Nothing on this strip turns
     * on the difference between *11 months* and *12*, and a calendar
     * calculation invites a precision the underlying date does not
     * have.
     *
     * @param int $stamp
     * @param int $now
     * @return string
     */
    public static function agePhrase($stamp, $now)
    {
        $days = (int)floor(
            (strtotime(date('Y-m-d', $now)) - strtotime(date('Y-m-d', $stamp)))
            / 86400
        );
        if ($days < 0) {
            // A declared `last_seen` may sit in the future. Saying
            // "today" is wrong in a direction nobody can act on, so it
            // says so.
            return __('dated in the future');
        }
        if ($days === 0) {
            return __('today');
        }
        if ($days === 1) {
            return __('yesterday');
        }
        if ($days < 31) {
            return sprintf(__('%s days ago'), $days);
        }
        if ($days < 365) {
            $months = (int)floor($days / 30);
            return sprintf(
                __n('%s month ago', '%s months ago', $months),
                $months
            );
        }
        $years = (int)floor($days / 365);
        return sprintf(__n('%s year ago', '%s years ago', $years), $years);
    }

    /**
     * The banner's note about rows reached through `value2`.
     *
     * Absent, not empty, when nothing matched that way — which is the
     * common case, and a note reading *0 occurrences have it as the
     * second half* would be noise on every ordinary value.
     *
     * @param array $second `Value::value2CountFor`
     * @return string|null
     */
    public static function value2Note(array $second)
    {
        if (empty($second)) {
            return null;
        }
        $total = 0;
        foreach ($second as $row) {
            $total += $row['count'];
        }
        return sprintf(
            __n(
                '%1$s occurrence has it as the second half of a %2$s',
                '%1$s occurrences have it as the second half of a %2$s',
                $total
            ),
            number_format($total),
            $second[0]['type']
        );
    }
}
