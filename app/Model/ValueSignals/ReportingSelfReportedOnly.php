<?php

/**
 * The viewer's own organisation is the only one reporting this value.
 *
 * `reporting.independent_orgs` already scores one organisation; this
 * row says *whose* assertion it is, because a record resting on your
 * own reporting alone is one you cannot cite back to yourself as
 * corroboration.
 *
 * It takes back part of what `independent_orgs` paid for that one
 * organisation, leaving your own sole report worth less than an outside
 * organisation's.
 */
class ReportingSelfReportedOnly extends ValueSignalBase
{
    public $id = 'reporting.self_reported_only';
    public $group = 'Reporting';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('orgs');
    public $tab = 'occurrences';

    public function __construct()
    {
        $this->description = __(
            'Takes points off when your own organisation is the only one'
            . ' reporting this value: nobody else backs it up.'
        );
        $this->help = array(
            'name' => __('Only you report it'),
            'what' => __(
                'Fires when the one organisation reporting this value is'
                . ' yours. Independent reporters already paid your'
                . ' organisation its points; this takes part of them back,'
                . ' because your own report is not corroboration you can'
                . ' cite.'
            ),
            'how' => __(
                'Worth {only_you} points when only your organisation'
                . ' reports it. Silent otherwise.'
            ),
            'settings' => array(
                'only_you' => __(
                    'The further below zero, the less a value backed only'
                    . ' by your own reporting scores. At 0 your report'
                    . ' counts like anybody else\'s.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Your own team\'s reporting should count'
                        . ' in full'),
                    'do' => __('Set only_you to 0.'),
                ),
                array(
                    'want' => __('A value only you report should earn'
                        . ' nothing for it'),
                    'do' => __('Set only_you to minus Independent'
                        . ' reporters\' per_org, e.g. -7, so the two'
                        . ' cancel.'),
                ),
            ),
        );
        $this->points_schema = array(
            'only_you' => array(
                'type' => 'int',
                'default' => -4,
                'label' => __('Points when only your organisation'
                    . ' reports it'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $own = (int)($context['viewer']['org_id'] ?? 0);
        $orgs = isset($context['orgs']) ? $context['orgs'] : array();
        if ($own === 0 || count($orgs) !== 1
            || (int)($orgs[0]['id'] ?? 0) !== $own
        ) {
            return null;
        }
        $events = (int)($context['occurrences']['events'] ?? 0);
        $evidence = $events === 1
            ? __('In one of your events, and no other organisation\'s')
            : sprintf(
                __('In %d of your events, and no other organisation\'s'),
                $events
            );
        $feeds = (int)($context['feeds']['count'] ?? 0);
        if ($feeds > 0) {
            $evidence .= sprintf(
                $feeds === 1
                    ? __('; %d feed also lists it')
                    : __('; %d feeds also list it'),
                $feeds
            );
        }
        return $this->row(
            $this->points($config, 'only_you'),
            __('Only your organisation reported it'),
            $evidence,
            $context,
            $this->stampAsOf(
                $context['occurrences']['newest'] ?? null,
                $context
            )
        );
    }
}
