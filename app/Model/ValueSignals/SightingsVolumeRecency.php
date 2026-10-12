<?php

/**
 * How much this value has been seen, and how recently.
 *
 * Volume and recency in one row rather than two — *"47 sightings from
 * 4 orgs, last 2 days ago"* — because they are not independent
 * readings: four hundred
 * sightings that all stopped a year ago is one statement, not a strong
 * one and a weak one to be netted.
 *
 * **Logarithmic in volume, and that is the judgement.** The step from
 * 1 sighting to 10 says far more than the step from 400 to 410, so the
 * contribution saturates: `saturation` is the count at which the signal
 * is fully paid, and everything beyond it is worth the cap: with
 * `cap 24` and `saturation 50`, 47 sightings and 418 both land at
 * +24.
 *
 * **Recency is a factor, not an addend**, so it cannot rescue a value
 * nobody has seen: a stale sighting history scales the whole row down
 * rather than subtracting a fixed penalty from it.
 *
 * **Only type-0 reports count.** A false positive argues the value is
 * benign and an expiration that it is over; counted as volume, either
 * would lift the row on the report disputing it. They are read by
 * `sightings.false_positive` and the relevance clock instead.
 *
 * Absence fires as `none_recent`, and only on genuine absence — a
 * sighting set an exclusion emptied is not a value nobody sighted, and
 * `ValueSignalBase::absenceFires()` is where that rule lives.
 *
 * **Trust-weighted** — a sighting is
 * attributable to an organisation, so the count that feeds the
 * saturation curve becomes a *weighted* count of sightings. It goes in
 * before the logarithm rather than after it, because a factor applied
 * to the finished points would discount a `D`-graded organisation's
 * four hundred sightings by a quarter, where discounting the *count*
 * puts them where four hundred quarter-weight sightings belong on the
 * curve: the whole judgement in this signal is that volume saturates,
 * and a weighting that skipped the curve would not be weighting
 * volume.
 */
class SightingsVolumeRecency extends ValueSignalBase
{
    public $id = 'sightings.volume_recency';
    public $group = 'Sightings';
    public $evidence_class = self::EVIDENCE_ROW;
    public $reads = array('sightings');
    public $absence_key = 'none_recent';
    public $tab = 'sightings';

    public function __construct()
    {
        $this->description = __(
            'Adds points for sightings of the value: the first few count'
            . ' most, and a history that has gone quiet counts for less.'
        );
        $this->help = array(
            'name' => __('Sightings'),
            'what' => __(
                'How many sightings organisations reported, and how long'
                . ' ago the last one was. False-positive and expiration'
                . ' reports are not sightings here. Going from 1 to 10'
                . ' sightings says far more than from 400 to 410, so the'
                . ' points flatten out.'
            ),
            'how' => __(
                'Climbs on a curve to {cap} points at {saturation}'
                . ' sightings. Once the last one is over {stale_days} days'
                . ' old, the whole row is worth {stale_factor} times as'
                . ' much. No sighting at all is worth {none_recent}.'
            ),
            'note' => __(
                'With the shipped numbers, 1 sighting is worth about 4'
                . ' points, 10 about 15, and 50 or more the full 24.'
            ),
            'settings' => array(
                'cap' => __('The most sightings can add.'),
                'none_recent' => __(
                    'Points when nobody has sighted the value. Lower it to'
                    . ' push unsighted values down.'
                ),
                'saturation' => __(
                    'How many sightings earn the full cap. Lower it and a'
                    . ' handful counts for a lot.'
                ),
                'stale_days' => __(
                    'Days after the last sighting before the history counts'
                    . ' as stale.'
                ),
                'stale_factor' => __(
                    'What a stale history is worth: 1 keeps it whole, 0'
                    . ' makes it worthless.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('A handful of sightings should already'
                        . ' count fully'),
                    'do' => __('Lower saturation, e.g. to 10.'),
                ),
                array(
                    'want' => __('Old sightings should keep their weight'),
                    'do' => __('Set stale_factor to 1.'),
                ),
                array(
                    'want' => __('Sightings should outweigh the other'
                        . ' evidence'),
                    'do' => __('Raise cap, e.g. to 36.'),
                ),
            ),
        );
        $this->points_schema = array(
            'cap' => array(
                'type' => 'int',
                'default' => 24,
                'label' => __('Points at saturation'),
            ),
            'none_recent' => array(
                'type' => 'int',
                'default' => -1,
                'label' => __('Points when nobody has sighted it'),
            ),
        );
        $this->config_schema = array(
            'saturation' => array(
                'type' => 'int',
                'default' => 50,
                'label' => __('Sightings at which the signal is fully'
                    . ' paid'),
            ),
            'stale_days' => array(
                'type' => 'int',
                'default' => 90,
                'label' => __('Age past which sightings are discounted'),
            ),
            'stale_factor' => array(
                'type' => 'float',
                'default' => 0.5,
                'label' => __('What a stale sighting history is worth'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $sightings = isset($context['sightings']['seen'])
            && is_array($context['sightings']['seen'])
            ? $context['sightings']['seen']
            : array();
        $total = (int)($sightings['total'] ?? 0);
        if ($total === 0) {
            if (!$this->absenceFires($config, $context, 'sightings')) {
                return null;
            }
            $reports = (int)($context['sightings']['total'] ?? 0);
            return $this->row(
                $this->points($config, 'none_recent'),
                __('Nobody has sighted this value'),
                $reports > 0
                    ? __('Only false-positive or expiration reports,'
                        . ' which are not sightings')
                    : __('No sighting from any organisation'),
                $context
            );
        }

        $saturation = max(1, (int)$this->setting($config, 'saturation'));
        $weighted = ValueTrustTool::inForce($context, $config);
        $counted = $weighted
            ? ValueTrustTool::weigh(
                $context,
                $this->tallies($sightings)
            )
            : $total;
        $volume = min(1.0, log(1 + $counted) / log(1 + $saturation));
        $last = (int)($sightings['last_stamp'] ?? 0);
        $ageDays = $last > 0
            ? (int)floor((($context['now'] ?? time()) - $last) / 86400)
            : null;
        $stale = ($ageDays === null
            || $ageDays > (int)$this->setting($config, 'stale_days'));
        $factor = $stale
            ? (float)$this->setting($config, 'stale_factor')
            : 1.0;
        $points = $this->capped(
            $this->points($config, 'cap') * $volume * $factor,
            $this->points($config, 'cap')
        );

        $orgs = (int)($sightings['orgs'] ?? 0);
        $signal = sprintf(
            __('%1$s from %2$s, last %3$s'),
            sprintf(
                $total === 1 ? __('%d sighting') : __('%d sightings'),
                $total
            ),
            sprintf(
                $orgs === 1 ? __('%d org') : __('%d orgs'),
                $orgs
            ),
            $ageDays === null
                ? __('an unknown time ago')
                : $this->agoPhrase($ageDays)
        );
        $recent = (int)($sightings['recent'] ?? 0);
        $recentDays = (int)($sightings['recent_days'] ?? 30);
        $evidence = sprintf(
            __('%1$d in the last %2$d days'),
            $recent,
            $recentDays
        );
        if ($stale) {
            $evidence .= sprintf(
                __('; discounted to %d%% as a stale history'),
                (int)round($factor * 100)
            );
        }
        /*
         * Why this row names a *quantity* where
         * `reporting.independent_orgs` names grades: the count that
         * fed the curve is not on the page anywhere else, so a reader
         * comparing *"47 sightings"* against the points has no way to
         * find the 31 the grades left. The clause is appended over the
         * top, so a `G`-graded filer is still named.
         */
        if ($weighted && (int)round($counted) !== $total) {
            $evidence .= sprintf(
                __('; weighted to %d by your reliability grades'),
                (int)round($counted)
            );
        }
        if ($weighted) {
            $evidence = ValueTrustTool::appendClause(
                $context,
                $evidence,
                array_keys($this->tallies($sightings))
            );
        }

        return $this->row(
            $points,
            $signal,
            $evidence,
            $context,
            $this->stampAsOf($last, $context)
        );
    }

    /**
     * Sightings per organisation, with the ones this viewer cannot
     * attribute filed under id `0` — which `ValueTrustTool::factor()`
     * reads as `unrated`, so they weigh exactly what they weighed
     * before anybody was graded.
     *
     * A context that carries no `by_org` map falls back to the whole
     * total as one unattributed block, which is the same number the
     * unweighted path computes.
     *
     * @param array $sightings The context's sightings block
     * @return array orgId => count
     */
    private function tallies(array $sightings)
    {
        $byOrg = isset($sightings['by_org'])
            && is_array($sightings['by_org'])
            ? $sightings['by_org']
            : array();
        $anonymous = (int)($sightings['anonymous'] ?? 0);
        if (empty($byOrg) && $anonymous === 0) {
            return array(0 => (int)($sightings['total'] ?? 0));
        }
        if ($anonymous > 0) {
            $byOrg[0] = ($byOrg[0] ?? 0) + $anonymous;
        }
        return $byOrg;
    }
}
