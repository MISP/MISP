<?php

/**
 * The viewer's own organisation's sightings, set against everyone
 * else's.
 *
 * `sightings.volume_recency` counts how much the value was seen; this
 * row says whether it was seen *by you* — the nearest MISP gets to
 * "is this in my estate", since it holds sightings rather than
 * telemetry.
 *
 * Two poles: your organisation sighted it, or only others did. The
 * first pays less once your last sighting is past `stale_days`. The
 * second is worth nothing by default — not being seen by you is not
 * evidence against a value — and stays silent when an exclusion or the
 * evidence window removed sightings, since yours could be among them.
 */
class ExposureOwnEstate extends ValueSignalBase
{
    public $id = 'exposure.own_estate';
    public $group = 'Sightings';
    public $evidence_class = self::EVIDENCE_ROW;
    public $reads = array('sightings');
    public $tab = 'sightings';

    public function __construct()
    {
        $this->description = __(
            'Adds points when your own organisation has sighted this'
            . ' value, more when the sighting is recent.'
        );
        $this->help = array(
            'name' => __('Your own sightings'),
            'what' => __(
                'Whether your organisation reported a sighting of this'
                . ' value: evidence from your own estate rather than'
                . ' somebody else\'s. Silent when nobody has sighted it.'
            ),
            'how' => __(
                'Your sighting in the last {stale_days} days is worth'
                . ' {own} points, an older one {own_stale}. Sightings only'
                . ' by other organisations are worth {others_only}.'
            ),
            'settings' => array(
                'own' => __(
                    'What your organisation seeing it lately is worth.'
                    . ' Raise it to put what touches your estate first.'
                ),
                'own_stale' => __(
                    'What an old sighting of yours is still worth.'
                ),
                'others_only' => __(
                    'Points when others sighted it and you did not. Below'
                    . ' zero pushes down what only other estates have seen.'
                ),
                'stale_days' => __(
                    'For how many days your sighting counts as recent.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('What your own SOC saw should come'
                        . ' first'),
                    'do' => __('Raise own, e.g. to 12.'),
                ),
                array(
                    'want' => __('Values only other organisations saw'
                        . ' should rank lower'),
                    'do' => __('Lower others_only, e.g. to -3.'),
                ),
                array(
                    'want' => __('Your sightings should stay recent for'
                        . ' six months'),
                    'do' => __('Raise stale_days to 180.'),
                ),
            ),
        );
        $this->points_schema = array(
            'own' => array(
                'type' => 'int',
                'default' => 6,
                'label' => __('Points when your organisation sighted it'
                    . ' recently'),
            ),
            'own_stale' => array(
                'type' => 'int',
                'default' => 2,
                'label' => __('Points when your organisation\'s last'
                    . ' sighting is old'),
            ),
            'others_only' => array(
                'type' => 'int',
                'default' => 0,
                'label' => __('Points when only other organisations'
                    . ' sighted it'),
            ),
        );
        $this->config_schema = array(
            'stale_days' => array(
                'type' => 'int',
                'default' => 90,
                'label' => __('Age past which your sighting is old'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $own = (int)($context['viewer']['org_id'] ?? 0);
        $seen = isset($context['sightings']['seen'])
            && is_array($context['sightings']['seen'])
            ? $context['sightings']['seen']
            : array();
        $total = (int)($seen['total'] ?? 0);
        if ($own === 0 || $total === 0) {
            return null;
        }
        $mine = (int)($seen['by_org'][$own] ?? 0);
        $others = $total - $mine;

        if ($mine === 0) {
            if (!empty($context['excluded']['sightings'])) {
                return null;
            }
            return $this->row(
                $this->points($config, 'others_only'),
                __('Sighted elsewhere, not by your organisation'),
                sprintf(
                    $others === 1
                        ? __('%d sighting, from another organisation')
                        : __('%d sightings, all from other'
                            . ' organisations'),
                    $others
                ),
                $context,
                $this->stampAsOf($seen['last_stamp'] ?? null, $context)
            );
        }

        $last = (int)($seen['by_org_last'][$own] ?? 0);
        $ageDays = $last > 0
            ? (int)floor((($context['now'] ?? time()) - $last) / 86400)
            : null;
        $stale = ($ageDays === null
            || $ageDays > (int)$this->setting($config, 'stale_days'));
        $signal = sprintf(
            $mine === 1
                ? __('Your organisation sighted it once, %s')
                : __('Your organisation sighted it %2$d times, last %1$s'),
            $ageDays === null
                ? __('at an unknown time')
                : $this->agoPhrase($ageDays),
            $mine
        );
        return $this->row(
            $this->points($config, $stale ? 'own_stale' : 'own'),
            $signal,
            $others === 0
                ? __('No other organisation has sighted it')
                : sprintf(
                    $others === 1
                        ? __('%d more sighting from other organisations')
                        : __('%d more sightings from other'
                            . ' organisations'),
                    $others
                ),
            $context,
            $this->stampAsOf($last, $context)
        );
    }
}
