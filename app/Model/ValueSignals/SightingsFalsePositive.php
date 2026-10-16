<?php

/**
 * Somebody who looked at this value said it was wrong.
 *
 * The clearest negative evidence MISP holds: eleven false-positive
 * sightings on `8.8.8.8` are worth −26 threat-signed, which the benign
 * lean's polarity renders as **+26 supporting benign** without the
 * declaration changing.
 *
 * **Capped, because a false positive is a judgement and not a
 * measurement.** One organisation can file forty; the cap is what stops
 * that outweighing every other signal on the page, and the row names
 * the organisations so a reader can see whether the forty were one
 * voice.
 *
 * **Silent on absence, deliberately.** No false positive is the normal
 * state of nearly every value on an instance, and a ledger row saying
 * so on all of them is noise that would drown the rows that mean
 * something.
 *
 * **Trust-weighted** — a false positive from
 * a `D`-graded source is weaker evidence, and the weighting reaches
 * both halves of the arithmetic: the filings become a weighted count of
 * filings, and the extra-organisation term becomes `Σ factor − 1`,
 * which is `orgs − 1` exactly when nobody is graded. That second half
 * is what makes a `G` grade mean what it says — an organisation
 * whose evidence counts for nothing contributes no
 * filings *and* does not count as another voice, so it cannot
 * whitewash a value it controls by filing from one desk.
 */
class SightingsFalsePositive extends ValueSignalBase
{
    public $id = 'sightings.false_positive';
    public $group = 'Sightings';
    public $evidence_class = self::EVIDENCE_ROW;
    public $reads = array('sightings');
    /*
     * One of the two ledger-borne lean sources, so it anchors:
     * an organisation filing a false positive is saying what the value
     * *is*, not how well documented it is. Its silence on absence is
     * what makes it safe to anchor — there is no *nobody called it a
     * false positive* pole to be read as an argument for threat.
     */
    public $axis = self::AXIS_LEAN;
    // Each filer is a benign voice in the stance count.
    public $voice = true;
    public $tab = 'sightings';

    public function __construct()
    {
        $this->description = __(
            'False-positive sightings, and how many organisations filed'
            . ' them. Argues the value is harmless.'
        );
        $this->help = array(
            'name' => __('False-positive sightings'),
            'what' => __(
                'Somebody who looked at the value filed a sighting saying'
                . ' it is a false positive. Many filings from one'
                . ' organisation are one voice; each further organisation'
                . ' is another.'
            ),
            'how' => __(
                'Each false-positive sighting is drawn as {per} points,'
                . ' each organisation beyond the first adds'
                . ' {per_extra_org}, {cap} at most, in the value page\'s'
                . ' lean evidence.'
            ),
            'note' => __(
                'These points do not decide the reading. Every organisation'
                . ' that filed a false positive is already a vote for'
                . ' harmless; the points only size this row. Unticking the'
                . ' signal hides the row, and the votes still count.'
            ),
            'settings' => array(
                'per' => __(
                    'How large each false-positive sighting is drawn.'
                ),
                'per_extra_org' => __(
                    'How much each further organisation filing one adds.'
                ),
                'cap' => __('The most the row is drawn as.'),
            ),
            'recipes' => array(
                array(
                    'want' => __('False positives should contest a value'
                        . ' others flag sooner'),
                    'do' => __('Raise Thresholds → The lean →'
                        . ' Supermajority share, e.g. to 0.75.'),
                ),
                array(
                    'want' => __('An old false positive should count less'
                        . ' once reporters flag the value again'),
                    'do' => __('Lower Thresholds → The lean → Weight of an'
                        . ' old dispute, e.g. to 0.25.'),
                ),
                array(
                    'want' => __('One organisation\'s false positives'
                        . ' should count less'),
                    'do' => __('Grade it under Sources & reputation →'
                        . ' Organisation reputation.'),
                ),
            ),
        );
        $this->points_schema = array(
            'per' => array(
                'type' => 'int',
                'default' => -3,
                'label' => __('Points per false-positive sighting'),
            ),
            'per_extra_org' => array(
                'type' => 'int',
                'default' => -4,
                'label' => __('Further points per organisation beyond'
                    . ' the first'),
            ),
            'cap' => array(
                'type' => 'int',
                'default' => -26,
                'label' => __('Most this signal may contribute'),
            ),
        );
        /*
         * The per-sighting points, not the per-extra-org bonus: one
         * more sighting from an organisation already filing them is
         * linear to the cap, and it is also the change a reader can
         * actually make. A sighting from a *new* organisation is worth
         * more than this says, which is the safe direction for a
         * falsifier to err in.
         */
        $this->unit = array(
            'points' => 'per',
            'cap' => 'cap',
            'one' => __('One more false-positive sighting'),
            'many' => __('%d more false-positive sightings'),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $sightings = isset($context['sightings'])
            ? $context['sightings']
            : array();
        $fp = (int)($sightings['fp'] ?? 0);
        if ($fp === 0) {
            return null;
        }
        $orgs = max(1, (int)($sightings['fp_orgs'] ?? 1));
        $weighted = ValueTrustTool::inForce($context, $config);
        $tallies = $this->tallies($sightings, $fp);
        $filings = $weighted
            ? ValueTrustTool::weigh($context, $tallies)
            : $fp;
        $voices = $weighted
            ? ValueTrustTool::weighOrgs($context, array_keys($tallies))
            : $orgs;
        $points = $this->capped(
            $this->points($config, 'per') * $filings
                + $this->points($config, 'per_extra_org')
                    * max(0, $voices - 1),
            $this->points($config, 'cap')
        );

        $names = $weighted
            ? ValueTrustTool::annotate(
                $context,
                isset($sightings['fp_org_list'])
                    && is_array($sightings['fp_org_list'])
                    ? $sightings['fp_org_list']
                    : array()
            )
            : array();
        if (empty($names)) {
            $names = isset($sightings['fp_org_names'])
                ? $sightings['fp_org_names']
                : array();
        }
        if ($fp === 1) {
            $signal = empty($names)
                ? __('1 false-positive sighting')
                : sprintf(
                    __('1 false-positive sighting (%s)'),
                    $names[0]
                );
        } else {
            $signal = sprintf(
                __('%1$d false-positive sightings from %2$d'
                    . ' %3$s'),
                $fp,
                $orgs,
                $orgs === 1 ? __('org') : __('orgs')
            );
        }

        $evidence = empty($names)
            ? __('Filed by organisations that are not named to you')
            : implode(', ', $names);
        if ($weighted) {
            $evidence = ValueTrustTool::appendClause(
                $context,
                $evidence,
                array_keys($tallies)
            );
        }

        return $this->row(
            $points,
            $signal,
            $evidence,
            $context,
            $this->stampAsOf(
                $sightings['fp_last_stamp'] ?? null,
                $context
            )
        );
    }

    /**
     * False positives per organisation, with the ones this viewer
     * cannot attribute under id `0` — read as `unrated`, so they weigh
     * what they weighed before anybody was graded.
     *
     * A context built without a per-org map falls back to the
     * whole count as one unattributed block: the same number the
     * unweighted path computes, so an old context cannot change a
     * score by being old.
     *
     * @param array $sightings The context's sightings block
     * @param int $fp The total, for the fallback
     * @return array orgId => count
     */
    private function tallies(array $sightings, $fp)
    {
        $byOrg = isset($sightings['by_org_fp'])
            && is_array($sightings['by_org_fp'])
            ? $sightings['by_org_fp']
            : array();
        $anonymous = (int)($sightings['anonymous_fp'] ?? 0);
        if (empty($byOrg) && $anonymous === 0) {
            return array(0 => (int)$fp);
        }
        if ($anonymous > 0) {
            $byOrg[0] = ($byOrg[0] ?? 0) + $anonymous;
        }
        return $byOrg;
    }
}
