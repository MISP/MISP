<?php

/**
 * Whether anybody outside this instance is publishing the value too.
 *
 * Feed presence is corroboration from a source that never saw the
 * instance's own events, which is why it belongs in the ledger at all.
 * It is also the signal most easily double-counted: a feed that mirrors
 * the same OSINT the instance already ingested is not an independent
 * voice — three mirrors of one OSINT source are one piece of
 * corroboration, not three.
 *
 * That dedupe is the `feeds.mirrored` exclusion's job, and a feed
 * published by one of the value's own reporters is `feeds.reporters`';
 * this signal reads whatever survives both. What it owns is the cap: two
 * feeds is corroboration, twelve feeds is a popular blocklist entry,
 * and the difference between those two is not five times as much
 * evidence.
 *
 * Absence fires as `no_feed`, weakly. A value nobody else publishes is
 * mildly thinner than one several do, and the row keeps the reader from
 * wondering whether the feeds were checked.
 */
class LifecycleFeeds extends ValueSignalBase
{
    public $id = 'lifecycle.feeds';
    public $group = 'Lifecycle';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('feeds');
    public $absence_key = 'no_feed';
    public $tab = 'general';

    public function __construct()
    {
        $this->description = __(
            'Adds points for each enabled feed or server that also lists'
            . ' this value; takes a little off when none does.'
        );
        $this->help = array(
            'name' => __('Listed in feeds'),
            'what' => __(
                'Whether the value appears in the feeds and servers this'
                . ' instance has enabled and cached: an outside list'
                . ' agreeing with the record. Only cached sources are'
                . ' checked.'
            ),
            'how' => __(
                'Each feed listing it is worth {per_feed} points, up to'
                . ' {cap}. Listed nowhere: {no_feed}.'
            ),
            'settings' => array(
                'per_feed' => __('What one feed listing it is worth.'),
                'cap' => __('The most feeds can add.'),
                'no_feed' => __(
                    'Points when no feed lists it. At 0 that is not held'
                    . ' against the value.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Your feeds should weigh more'),
                    'do' => __('Raise per_feed to 8 and cap to 16.'),
                ),
                array(
                    'want' => __('A value no feed lists should not lose'
                        . ' points'),
                    'do' => __('Set no_feed to 0.'),
                ),
            ),
        );
        $this->points_schema = array(
            'per_feed' => array(
                'type' => 'int',
                'default' => 4,
                'label' => __('Points per feed carrying the value'),
            ),
            'cap' => array(
                'type' => 'int',
                'default' => 8,
                'label' => __('Most this signal may contribute'),
            ),
            'no_feed' => array(
                'type' => 'int',
                'default' => -2,
                'label' => __('Points when no feed carries it'),
            ),
        );
        $this->unit = array(
            'points' => 'per_feed',
            'cap' => 'cap',
            'one' => __('One enabled feed carrying it'),
            'many' => __('%d enabled feeds carrying it'),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $feeds = isset($context['feeds']) ? $context['feeds'] : array();
        $count = (int)($feeds['count'] ?? 0);
        if ($count === 0) {
            if (!$this->absenceFires($config, $context, 'feeds')) {
                return null;
            }
            return $this->row(
                $this->points($config, 'no_feed'),
                __('No enabled feed carries it'),
                (int)($feeds['checked'] ?? 0) > 0
                    ? sprintf(
                        __('%d cached sources checked'),
                        (int)$feeds['checked']
                    )
                    : __('Checked against the cached sources you may'
                        . ' see'),
                $context
            );
        }
        $points = $this->capped(
            $this->points($config, 'per_feed') * $count,
            $this->points($config, 'cap')
        );
        $names = isset($feeds['names']) ? $feeds['names'] : array();
        return $this->row(
            $points,
            sprintf(
                $count === 1
                    ? __('Present in %d enabled feed')
                    : __('Present in %d enabled feeds'),
                $count
            ),
            empty($names)
                ? __('Cached feed content')
                : implode(', ', array_slice($names, 0, 4)),
            $context
        );
    }
}
