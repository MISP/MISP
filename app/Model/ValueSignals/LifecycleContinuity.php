<?php

/**
 * Whether the reporting is continuous or a single burst.
 *
 * *"Fourteen months without a month of silence"* is a genuinely
 * different reading from *how much* and *how recently*. A hundred
 * reports inside one week and a hundred spread evenly over two years
 * are the same volume and not the same kind of evidence: the second is
 * infrastructure somebody keeps finding, the first is one incident
 * reported many times.
 *
 * **The longest unbroken run of months, not the span.** A value
 * reported in 2023 and again last week has a two-year span and no
 * continuity at all; counting the run is what makes the row's own
 * sentence true.
 *
 * **Aggregate evidence, so never windowed.** The months come
 * from a grouped count over occurrence timestamps, which is cheap at
 * any cardinality — and a 90-day window would cap every long-lived
 * value at three months of continuity, turning the signal's own
 * subject into an artefact of the budget.
 *
 * Silent below `min_months`: two consecutive months is not a pattern,
 * and a row claiming one would be the engine over-reading its data.
 */
class LifecycleContinuity extends ValueSignalBase
{
    public $id = 'lifecycle.continuity';
    public $group = 'Lifecycle';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('activity');
    public $tab = 'timeline';

    public function __construct()
    {
        $this->description = __(
            'Adds points for the longest streak of consecutive months in'
            . ' which the value was reported.'
        );
        $this->help = array(
            'name' => __('Steady reporting'),
            'what' => __(
                'Infrastructure reported month after month is more likely'
                . ' to be real and long-lived. This finds the longest'
                . ' unbroken run of months with at least one report.'
            ),
            'how' => __(
                'Each month of the streak is worth {per_month} points, up'
                . ' to {cap}. A streak shorter than {min_months} months'
                . ' scores nothing.'
            ),
            'settings' => array(
                'per_month' => __('What one month of the streak is'
                    . ' worth.'),
                'cap' => __('The most a streak can add.'),
                'min_months' => __(
                    'The shortest streak that counts at all.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Long-running infrastructure should'
                        . ' stand out'),
                    'do' => __('Raise per_month to 2 and cap to 24.'),
                ),
                array(
                    'want' => __('Two months in a row should already'
                        . ' count'),
                    'do' => __('Lower min_months to 2.'),
                ),
            ),
        );
        $this->points_schema = array(
            'per_month' => array(
                'type' => 'int',
                'default' => 1,
                'label' => __('Points per unbroken month'),
            ),
            'cap' => array(
                'type' => 'int',
                'default' => 12,
                'label' => __('Most this signal may contribute'),
            ),
        );
        $this->config_schema = array(
            'min_months' => array(
                'type' => 'int',
                'default' => 3,
                'label' => __('Months of continuity before this fires'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $activity = isset($context['activity'])
            ? $context['activity']
            : array();
        $run = (int)($activity['longest_run'] ?? 0);
        $minimum = max(1, (int)$this->setting($config, 'min_months'));
        if ($run < $minimum) {
            return null;
        }
        $points = $this->capped(
            $this->points($config, 'per_month') * $run,
            $this->points($config, 'cap')
        );
        $active = (int)($activity['active_months'] ?? $run);
        $span = (int)($activity['span_months'] ?? $active);
        return $this->row(
            $points,
            sprintf(
                __('Longest streak: %d months in a row'),
                $run
            ),
            sprintf(
                __('Reported in %1$d of the %2$d months it has'
                    . ' existed'),
                $active,
                max($span, $active)
            ),
            $context
        );
    }
}
