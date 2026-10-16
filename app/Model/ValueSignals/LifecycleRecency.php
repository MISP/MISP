<?php

/**
 * How recently anybody reported this value.
 *
 * The signal-strength reading of age, and deliberately not the relevance axis.
 * Relevance asks *does this still matter today* and answers with a TTL,
 * a runway and an expiry; this asks the narrower
 * question a ledger can answer — **is the record still being added
 * to** — and pays a few points for a yes.
 *
 * Keeping both is not double-counting, because they read different
 * clocks. Relevance runs off the last *independent corroboration* and
 * can expire a value nobody has re-reported; this runs off the last
 * occurrence of any kind, so a value one organisation keeps re-encoding
 * scores here and still ages out there. Where they agree, they agree in
 * different vocabulary on different axes; where they disagree, the
 * disagreement is the interesting thing and both are on screen.
 *
 * **Interpolated between the two ends**, so there is no cliff: a value
 * last reported the day after `recent_days` is worth marginally less
 * than one reported the day before it, not `recent` less. A cliff in a
 * ledger row is a place where two readers with the same evidence and
 * one day between their page loads get materially different numbers.
 */
class LifecycleRecency extends ValueSignalBase
{
    public $id = 'lifecycle.recency';
    public $group = 'Lifecycle';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('occurrences');
    public $tab = 'occurrences';

    public function __construct()
    {
        $this->description = __(
            'Adds points when the value was reported recently, and takes'
            . ' points off once nobody has reported it for a long time.'
        );
        $this->help = array(
            'name' => __('Recently reported'),
            'what' => __(
                'How long ago anybody last reported this value.'
            ),
            'how' => __(
                'Reported in the last {recent_days} days: {recent} points.'
                . ' Not for {old_days} days or more: {old}. In between it'
                . ' slides from one to the other.'
            ),
            'settings' => array(
                'recent' => __('What a fresh report is worth.'),
                'old' => __(
                    'What a long-untouched value is worth. At 0 age is not'
                    . ' held against it.'
                ),
                'recent_days' => __('For how many days a report is'
                    . ' fresh.'),
                'old_days' => __('After how many days a value counts as'
                    . ' old.'),
            ),
            'recipes' => array(
                array(
                    'want' => __('Fresh indicators should clearly win'
                        . ' (triage)'),
                    'do' => __('Raise recent to 12 and lower recent_days'
                        . ' to 14.'),
                ),
                array(
                    'want' => __('Old values should not lose points'
                        . ' (investigations)'),
                    'do' => __('Set old to 0.'),
                ),
                array(
                    'want' => __('Anything from the last quarter should'
                        . ' count as fresh'),
                    'do' => __('Raise recent_days to 90.'),
                ),
            ),
        );
        $this->points_schema = array(
            'recent' => array(
                'type' => 'int',
                'default' => 8,
                'label' => __('Points for a value reported recently'),
            ),
            'old' => array(
                'type' => 'int',
                'default' => -4,
                'label' => __('Points for a value nobody has touched'),
            ),
        );
        $this->config_schema = array(
            'recent_days' => array(
                'type' => 'int',
                'default' => 30,
                'label' => __('Days within which a report counts as'
                    . ' recent'),
            ),
            'old_days' => array(
                'type' => 'int',
                'default' => 365,
                'label' => __('Days after which it counts as old'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $occurrences = isset($context['occurrences'])
            ? $context['occurrences']
            : array();
        $newest = (int)($occurrences['newest'] ?? 0);
        if ($newest === 0) {
            return null;
        }
        $now = (int)($context['now'] ?? time());
        $days = (int)floor(($now - $newest) / 86400);
        $recentDays = (int)$this->setting($config, 'recent_days');
        $oldDays = max(
            $recentDays + 1,
            (int)$this->setting($config, 'old_days')
        );
        $recent = $this->points($config, 'recent');
        $old = $this->points($config, 'old');

        if ($days <= $recentDays) {
            $points = $recent;
        } elseif ($days >= $oldDays) {
            $points = $old;
        } else {
            $travelled = ($days - $recentDays)
                / ($oldDays - $recentDays);
            $points = $recent + ($old - $recent) * $travelled;
        }

        return $this->row(
            $points,
            sprintf(
                __('Last reported %s'),
                $this->agoPhrase($days)
            ),
            sprintf(
                __('Recent under %1$d days, old after %2$d'),
                $recentDays,
                $oldDays
            ),
            $context,
            $this->stampAsOf($newest, $context)
        );
    }
}
