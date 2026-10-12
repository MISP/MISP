<?php

App::uses('WarninglistCategory', 'Tools');

/**
 * MISP knows the value as shared infrastructure, and organisations
 * report it as a threat anyway.
 *
 * The contradiction that was on screen before anything computed it, and
 * the reason the warninglist signal weights a `known` hit at zero
 * rather than netting it off against the reporting. Both facts are
 * true: the value really is a CDN front or a hosting range, *and*
 * several organisations really did put it in an event with `to_ids`
 * set. Neither discounts the other.
 *
 * What arithmetic would do with that pair is pick the heavier side, and
 * both answers it can reach are wrong. Calling it a threat hides that
 * the value cannot be attributed to one tenant, so a reader blocks a
 * CDN edge. Calling it benign hides that people are reporting it, so a
 * reader stops looking at the one value several of their peers thought
 * worth flagging. The honest answer is the contradiction itself, which
 * is what this rule emits.
 *
 * **A single report is not a contradiction**, which is what
 * `min_independent_reports` is for. One organisation tagging a CDN
 * address is a mistake in one event, and a page that escalated on it
 * would escalate on every large hosting range MISP has ever seen. Three
 * organisations arriving at the same value independently is a pattern,
 * and a pattern against a `known` list is worth a reader's attention.
 */
class ConflictKnownInfrastructure extends ValueEscalationBase
{
    public $id = 'conflict:known-infrastructure-vs-reporting';
    public $reads = array('warninglist', 'orgs');
    public $tab = 'general';

    public function __construct()
    {
        $this->description = __(
            'Marks the value contested when a warninglist knows it as'
            . ' shared infrastructure and several organisations have'
            . ' taken a side on it.'
        );
        $this->help = array(
            'name' => __('Shared infrastructure that gets reported'),
            'what' => __(
                'A value MISP knows as shared infrastructure, such as a'
                . ' CDN edge or a hosting range, that organisations report.'
                . ' Shared does not mean harmless, and reported does not'
                . ' make it one tenant\'s: blocking it may hit everyone'
                . ' else on it, ignoring it may miss what peers flagged.'
            ),
            'how' => __(
                'Fires when the value is on a {warninglist_category} list'
                . ' and at least {min_independent_reports} organisations'
                . ' have taken a side on it. The reading is then contested,'
                . ' whatever the count of organisations would have said.'
            ),
            'note' => __(
                'It counts organisations on either side, those calling it'
                . ' a false positive as well as those flagging it.'
                . ' Unticked, the organisations are counted as for any'
                . ' value, and only a known_hit below zero (Signals →'
                . ' lifecycle.warninglist) can still contest a threat'
                . ' reading.'
            ),
            'settings' => array(
                'warninglist_category' => __(
                    'Which kind of list must match. A list\'s category is'
                    . ' set under Sources & reputation → Warninglist'
                    . ' categories.'
                ),
                'min_independent_reports' => __(
                    'The fewest organisations for the rule to fire. One'
                    . ' organisation tagging a CDN address is a mistake in'
                    . ' one event; several arriving at it separately is a'
                    . ' pattern.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Let the organisations decide a value on'
                        . ' a CDN or hosting list'),
                    'do' => __('Untick this rule.'),
                ),
                array(
                    'want' => __('Contest it only when many organisations'
                        . ' report it'),
                    'do' => __('Raise min_independent_reports, e.g. to'
                        . ' 6.'),
                ),
                array(
                    'want' => __('Contest it as soon as one organisation'
                        . ' reports it'),
                    'do' => __('Set min_independent_reports to 1.'),
                ),
            ),
        );
        $this->when_schema = array(
            'warninglist_category' => array(
                'type' => 'string',
                'default' => WarninglistCategory::KNOWN,
                'options' => WarninglistCategory::CATEGORIES,
                'label' => __('The category of list that must match'),
            ),
            'min_independent_reports' => array(
                'type' => 'int',
                'default' => 3,
                'label' => __('Organisations reporting it, at least'),
            ),
        );
    }

    public function fires(array $context, array $config)
    {
        $category = $this->when($config, 'warninglist_category');
        $lists = $this->listsInCategory($context, $category);
        if (empty($lists)) {
            return null;
        }
        $orgs = $this->orgCount($context);
        $minimum = (int)$this->when($config, 'min_independent_reports');
        if ($orgs < $minimum) {
            return null;
        }
        return array(
            'prose' => sprintf(
                __('MISP knows this as shared infrastructure, and %d'
                    . ' organisations report it as a threat anyway.'
                    . ' Both are true; neither discounts the other.'),
                $orgs
            ),
            'evidence' => sprintf(
                __('%1$s · %2$d reporting organisations'),
                implode(', ', $lists),
                $orgs
            ),
        );
    }
}
