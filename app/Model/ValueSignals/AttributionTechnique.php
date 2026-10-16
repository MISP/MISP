<?php

/**
 * Which ATT&CK techniques this value's occurrences are marked with.
 *
 * Weaker than an actor attribution and separate from it, because it
 * answers a different question: *"what was it used to do"* rather than
 * *"who used it"*. A technique also travels further — an analyst tags
 * `T1071.001` on anything speaking HTTP to a C2 — so the shipped
 * weights keep it below the galaxy row.
 *
 * **Silent on absence.** Most occurrences of most values carry no
 * technique, and the absence argues nothing: the value may simply
 * never have been the subject of an analysis that used the matrix.
 * `attribution.galaxy` fires on absence because *no attribution at all*
 * is a statement; *no technique* is not.
 */
class AttributionTechnique extends ValueSignalBase
{
    public $id = 'attribution.technique';
    public $group = 'Attribution';
    public $evidence_class = self::EVIDENCE_ROW;
    public $reads = array('galaxies');
    public $tab = 'general';

    public function __construct()
    {
        $this->description = __(
            'Adds points for each ATT&CK technique tagged on this value.'
        );
        $this->help = array(
            'name' => __('ATT&CK techniques'),
            'what' => __(
                'MITRE ATT&CK techniques, or galaxies shaped like them,'
                . ' tagged on the value\'s occurrences: somebody mapped'
                . ' what the indicator is used for.'
            ),
            'how' => __(
                'Each distinct technique is worth {per_technique} points,'
                . ' up to {cap}.'
            ),
            'settings' => array(
                'per_technique' => __('What one technique is worth.'),
                'cap' => __('The most techniques can add.'),
            ),
            'recipes' => array(
                array(
                    'want' => __('ATT&CK mapping should be strong'
                        . ' evidence'),
                    'do' => __('Raise per_technique to 6 and cap to 18.'),
                ),
                array(
                    'want' => __('Ignore technique tags'),
                    'do' => __('Untick the signal.'),
                ),
            ),
        );
        $this->points_schema = array(
            'per_technique' => array(
                'type' => 'int',
                'default' => 3,
                'label' => __('Points per distinct technique'),
            ),
            'cap' => array(
                'type' => 'int',
                'default' => 9,
                'label' => __('Most this signal may contribute'),
            ),
        );
        $this->unit = array(
            'points' => 'per_technique',
            'cap' => 'cap',
            'one' => __('One attack technique named on an occurrence'),
            'many' => __('%d attack techniques named on the'
                . ' occurrences'),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $galaxies = isset($context['galaxies'])
            ? $context['galaxies']
            : array();
        $techniques = isset($galaxies['techniques'])
            ? $galaxies['techniques']
            : array();
        if (empty($techniques)) {
            return null;
        }
        arsort($techniques);
        $points = $this->capped(
            $this->points($config, 'per_technique') * count($techniques),
            $this->points($config, 'cap')
        );
        $ids = array_keys($techniques);
        $lead = $ids[0];
        $occurrences = (int)$techniques[$lead];
        $signal = count($ids) === 1
            ? sprintf(
                __('%1$s on %2$d %3$s'),
                $lead,
                $occurrences,
                $occurrences === 1
                    ? __('occurrence')
                    : __('occurrences')
            )
            : sprintf(
                __('%1$d techniques, led by %2$s'),
                count($ids),
                $lead
            );
        return $this->row(
            $points,
            $signal,
            implode(', ', array_slice($ids, 0, 6)),
            $context
        );
    }
}
