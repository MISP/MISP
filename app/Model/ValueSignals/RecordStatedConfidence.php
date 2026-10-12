<?php

App::uses('ValueStatementTool', 'Tools/ValueIntelligence');
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');

/**
 * What the reporters said about their own claim.
 *
 * MISP has three ways for a reporter to say how sure it is: the
 * admiralty scale's information credibility (*confirmed by other
 * sources* … *improbable*), and the estimative-language likelihood and
 * analytic-confidence predicates. Each taxonomy numbers its entries,
 * and this reads that number — the midpoint states nothing, the top
 * pays the full `scale`, the bottom takes it off.
 *
 * It is the one signal-strength row that can tell two single-reporter values
 * apart on what the reporter knew rather than on how much record
 * there is.
 *
 * **Weighted by who said it.** Each organisation's statement counts at
 * its grade factor, capped at one: a source graded `A` stating *confirmed*
 * says no more than an ungraded one, an `E` says a quarter of it, and
 * `G` nothing. The figure is the mean over the organisations that
 * stated anything, so one confident reporter and one doubtful one
 * cancel.
 *
 * **Silent on absence.** Few reporters state a confidence at all, and
 * a reporter that did not is not saying it is unsure.
 */
class RecordStatedConfidence extends ValueSignalBase
{
    public $id = 'record.stated_confidence';
    public $group = 'Reporting';
    public $evidence_class = self::EVIDENCE_ROW;
    public $reads = array('statements');
    public $tab = 'occurrences';

    public function __construct()
    {
        $this->description = __(
            'Adds points when reporters tagged their report as confident,'
            . ' and takes points off when they tagged doubt.'
        );
        $this->help = array(
            'name' => __('Reporters\' stated confidence'),
            'what' => __(
                'Some reporters say how sure they are, with the'
                . ' admiralty-scale credibility tags or the'
                . ' estimative-language tags. The top of a scale ("confirmed'
                . ' by other sources") is full confidence, the middle is'
                . ' neutral, the bottom is doubt. Several reporters are'
                . ' averaged.'
            ),
            'how' => __(
                'Full confidence is worth {scale} points, full doubt as'
                . ' much taken off, the middle nothing. Silent when nobody'
                . ' tagged anything.'
            ),
            'note' => __(
                'Organisation grades can only lower this: a statement from'
                . ' an organisation graded A counts the same as an ungraded'
                . ' one.'
            ),
            'settings' => array(
                'scale' => __(
                    'How far a stated confidence can move the score, either'
                    . ' way. Raise it to let labelled reports stand out.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Reward reporters who state their'
                        . ' confidence'),
                    'do' => __('Raise scale, e.g. to 15.'),
                ),
                array(
                    'want' => __('Ignore what reporters say about their'
                        . ' own claims'),
                    'do' => __('Untick the signal.'),
                ),
            ),
        );
        $this->points_schema = array(
            'scale' => array(
                'type' => 'int',
                'default' => 9,
                'label' => __('Points for the highest stated confidence'
                    . ' (the lowest takes as many off)'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $byOrg = ValueStatementTool::confidenceByOrg($context);
        if (empty($byOrg)) {
            return null;
        }
        $weighted = ValueTrustTool::inForce($context, $config);
        $sum = 0.0;
        $parts = array();
        foreach ($byOrg as $orgId => $entry) {
            $w = $weighted
                ? min(1.0, ValueTrustTool::factor($context, $orgId))
                : 1.0;
            $sum += $w * $entry['reading'];
            $parts[] = sprintf('%s: %s',
                ValueStatementTool::orgName($context, $orgId),
                implode(', ', array_map(array($this, 'tagLabel'),
                    $entry['tags'])));
        }
        $figure = $sum / count($byOrg);
        $points = $this->points($config, 'scale') * $figure;

        $count = count($byOrg);
        if ($figure > 0.0) {
            $signal = __n('The reporter states confidence in it',
                '%d reporters state confidence in it, on balance', $count);
        } elseif ($figure < 0.0) {
            $signal = __n('The reporter states doubt about it',
                '%d reporters state doubt about it, on balance', $count);
        } else {
            $signal = __n('The reporter states no confidence either way',
                '%d reporters state no confidence either way, on balance',
                $count);
        }
        $evidence = implode('; ', $parts);
        if ($weighted) {
            $evidence = ValueTrustTool::appendClause($context, $evidence,
                array_keys($byOrg));
        }
        return $this->row(
            $points,
            sprintf($signal, $count),
            $evidence,
            $context
        );
    }

    /**
     * `admiralty-scale:information-credibility="2"` as *credibility 2*.
     *
     * @param string $name
     * @return string
     */
    public function tagLabel($name)
    {
        $parsed = ValueStatementTool::parse($name);
        if ($parsed === null) {
            return $name;
        }
        $labels = array(
            'admiralty-scale:information-credibility' => __('credibility'),
            'estimative-language:likelihood-probability' => __('likelihood'),
            'estimative-language:confidence-in-analytic-judgment' =>
                __('analytic confidence'),
        );
        $label = $labels[$parsed['predicate']] ?? $parsed['predicate'];
        return $label . ' ' . str_replace('-', ' ', $parsed['value']);
    }
}
