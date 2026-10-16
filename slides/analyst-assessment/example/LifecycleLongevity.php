<?php

/**
 * How long this value has been on record.
 *
 * The example custom signal from the Analyst Assessment deck. Drop it
 * in `app/Lib/ValueSignals/` and the next page load discovers it; add
 * its id to a profile and it starts scoring.
 *
 * The judgement it encodes: a value first reported nine years ago and
 * still being reported is a different thing from one that appeared
 * last week. The shipped catalogue scores how *recently* a value was
 * reported (`lifecycle.recency`) and how *continuously*
 * (`lifecycle.continuity`), but nothing scores how long it has stood.
 */
class LifecycleLongevity extends ValueSignalBase
{
    public $id = 'lifecycle.longevity';
    public $group = 'Lifecycle';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('occurrences');
    public $source = 'Occurrences';

    public function __construct()
    {
        $this->description = __(
            'How long this value has been on record, from its oldest'
            . ' occurrence to today.'
        );
        $this->points_schema = array(
            'established' => array(
                'type' => 'int',
                'default' => 6,
                'label' => __('Points once it is established'),
            ),
            'brief' => array(
                'type' => 'int',
                'default' => -2,
                'label' => __('Points while it is still new'),
            ),
        );
        $this->config_schema = array(
            'established_days' => array(
                'type' => 'int',
                'default' => 365,
                'label' => __('Days on record before it counts'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $oldest = (int)($context['occurrences']['oldest'] ?? 0);
        if ($oldest === 0) {
            return null;
        }
        $now = (int)($context['now'] ?? time());
        $days = (int)floor(($now - $oldest) / 86400);
        $threshold = (int)$this->setting($config, 'established_days');
        $established = $days >= $threshold;

        return $this->row(
            $this->points($config, $established ? 'established' : 'brief'),
            sprintf(
                $established
                    ? __('On record for %s')
                    : __('First recorded %s'),
                $established
                    ? $this->spanPhrase($days)
                    : $this->agoPhrase($days)
            ),
            sprintf(
                __('Established once it has stood for %d days'),
                $threshold
            ),
            $context,
            $this->stampAsOf($oldest, $context)
        );
    }

    /**
     * A span the way the page says one, rather than a bare day count.
     *
     * @param int $days
     * @return string
     */
    private function spanPhrase($days)
    {
        if ($days >= 730) {
            return sprintf(__('%d years'), (int)floor($days / 365));
        }
        if ($days >= 365) {
            return __('a year');
        }
        return sprintf(__('%d months'), (int)floor($days / 30));
    }
}
