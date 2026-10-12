<?php

/**
 * Whether the record can date its own observations.
 *
 * The signal-strength reading of the fact that makes the relevance axis say
 * *timeline uncertain*: no `first_seen` on any occurrence, so nothing
 * records when the value was seen — only when its row was last
 * written.
 *
 * Take a phishing URL encoded two months after the incident.
 * Relevance says *the timeline is uncertain*; this says the quieter
 * thing next to it — **a record that cannot date its own observations
 * is a weaker record** — and the two readings have separate homes.
 *
 * **It does not measure encoding lag.** `Event.date` against
 * `Attribute.timestamp` looks like one and is not: `timestamp` is
 * last-modified — an edit, a tag, a sync update or a delete bumps it —
 * and `Event.date` is typed by an analyst, so it carries the same delay
 * the measurement would be looking for. MISP stores no created date for
 * an attribute at all.
 *
 * **Aggregate evidence, not row evidence.** The fact arrives as a
 * single-row `SUM` over `first_seen`, so it is cheap at any
 * cardinality and is read whole-history like every other aggregate.
 * A hot value keeps this row when the sighting and galaxy
 * signals bow out, which is the right way round: what it measures is
 * how honest the record's dates are, and that is exactly the sort of
 * thing worth knowing about a value too big to read.
 */
class RecordTemporalPrecision extends ValueSignalBase
{
    public $id = 'record.temporal_precision';
    public $group = 'Lifecycle';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('temporal');
    public $tab = 'timeline';

    public function __construct()
    {
        $this->description = __(
            'Adds points when a report says when the value was actually'
            . ' seen (first seen); takes one off when none does.'
        );
        $this->help = array(
            'name' => __('Dated observations'),
            'what' => __(
                'Whether any occurrence carries a first-seen date: when the'
                . ' value was observed, as opposed to when it was typed'
                . ' into MISP. A dated report can be placed on a timeline.'
            ),
            'how' => __(
                'Any occurrence dated: {dated} points. None: {undated}.'
            ),
            'settings' => array(
                'dated' => __('What a dated observation is worth.'),
                'undated' => __(
                    'Points when no occurrence is dated. At 0 that is not'
                    . ' held against the value.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Reward precise reporting more'),
                    'do' => __('Raise dated, e.g. to 8.'),
                ),
                array(
                    'want' => __('Missing dates should cost nothing'),
                    'do' => __('Set undated to 0.'),
                ),
            ),
        );
        $this->points_schema = array(
            'dated' => array(
                'type' => 'int',
                'default' => 4,
                'label' => __('Points when an occurrence carries'
                    . ' first_seen'),
            ),
            'undated' => array(
                'type' => 'int',
                'default' => -1,
                'label' => __('Points when none does'),
            ),
        );
        /*
         * `lagged` points and their `lag_days` threshold were here,
         * deducting 4 for an encoding date that "lags the event". They
         * are gone with the measurement behind them: `Attribute
         * .timestamp` is last-modified, not created, and `Event.date`
         * is typed by an analyst — see `Value::recordSummaryFor()`.
         * This signal was the only place that unsound number reached
         * the ledger, so removing it takes it out of the verdict.
         *
         * What remains is the fact MISP can actually answer: does any
         * occurrence carry `first_seen`.
         */
        $this->config_schema = array();
    }

    public function evaluate(array $context, array $config)
    {
        $temporal = isset($context['temporal'])
            ? $context['temporal']
            : array();
        $occurrences = (int)($temporal['occurrences'] ?? 0);
        if ($occurrences === 0) {
            return null;
        }
        $dated = (int)($temporal['with_first_seen'] ?? 0);
        $points = $dated > 0
            ? $this->points($config, 'dated')
            : $this->points($config, 'undated');

        $evidence = array();
        $evidence[] = $dated > 0
            ? sprintf(
                __('%1$d of %2$d occurrences set first_seen'),
                $dated,
                $occurrences
            )
            : __('no occurrence carries a first-seen date');

        $signal = $dated === 0
            ? __('The record never says when it was seen')
            : __('The record dates its own observations');

        return $this->row(
            $points,
            $signal,
            implode('; ', $evidence),
            $context
        );
    }
}
