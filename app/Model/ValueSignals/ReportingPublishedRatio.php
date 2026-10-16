<?php

/**
 * How much of the reporting was actually published.
 *
 * A draft event is a claim its own organisation has not yet stood
 * behind, so the same evidence in a published event is worth more.
 *
 * **Scaled rather than banded**, because the ratio is the evidence: a
 * value published in five of seven events is not in the same position
 * as one published in one of seven, and two thresholds would flatten
 * that into three cases. `scale` is what full publication is worth and
 * the contribution is the ratio of it.
 *
 * **No floor.** At the shipped scale the ratio rounds to zero
 * only below one published event in eighteen, which no value on the
 * dev instance reaches (2026-10-01); a value with one published event
 * among many drafts reads `0`, between *none published* and the rest.
 */
class ReportingPublishedRatio extends ValueSignalBase
{
    public $id = 'reporting.published_ratio';
    public $group = 'Reporting';
    public $evidence_class = self::EVIDENCE_AGGREGATE;
    public $reads = array('publication');
    public $tab = 'occurrences';

    public function __construct()
    {
        $this->description = __(
            'Adds points for the share of events carrying this value that'
            . ' are published; takes a few off when none is.'
        );
        $this->help = array(
            'name' => __('Published events'),
            'what' => __(
                'Of the events carrying this value, how many are published.'
                . ' An unpublished event is a draft its organisation has'
                . ' not stood behind yet.'
            ),
            'how' => __(
                'Every event published is worth {scale} points; a partial'
                . ' share earns its fraction. None published is worth'
                . ' {none}. Needs at least {min_events} event(s) to speak.'
            ),
            'settings' => array(
                'scale' => __(
                    'Points when every event is published. Raise it where'
                    . ' publishing is a real quality gate.'
                ),
                'none' => __(
                    'Points when no event is published. Lower it to push'
                    . ' drafts down.'
                ),
                'min_events' => __(
                    'How many events the value needs before this signal'
                    . ' speaks. Changes no points.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Publishing means little in your'
                        . ' community'),
                    'do' => __('Set scale and none to 0, or untick the'
                        . ' signal.'),
                ),
                array(
                    'want' => __('Drafts should clearly count against a'
                        . ' value'),
                    'do' => __('Lower none, e.g. to -6.'),
                ),
                array(
                    'want' => __('Judge publication only on values seen'
                        . ' in several events'),
                    'do' => __('Raise min_events, e.g. to 3.'),
                ),
            ),
        );
        $this->points_schema = array(
            'scale' => array(
                'type' => 'int',
                'default' => 9,
                'label' => __('Points at full publication'),
            ),
            'none' => array(
                'type' => 'int',
                'default' => -2,
                'label' => __('Points when nothing is published'),
            ),
        );
        $this->config_schema = array(
            'min_events' => array(
                'type' => 'int',
                'default' => 1,
                'label' => __('Events needed before this fires'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $publication = isset($context['publication'])
            ? $context['publication']
            : array();
        $events = (int)($publication['events'] ?? 0);
        $published = (int)($publication['published'] ?? 0);
        if ($events < (int)$this->setting($config, 'min_events')
            || $events === 0
        ) {
            return null;
        }
        if ($published === 0) {
            return $this->row(
                $this->points($config, 'none'),
                $events === 1
                    ? __('The only event carrying it is unpublished')
                    : sprintf(
                        __('None of %d events is published'),
                        $events
                    ),
                __('An unpublished event is a claim its own'
                    . ' organisation has not stood behind yet'),
                $context
            );
        }
        $points = (int)round(
            $this->points($config, 'scale') * $published / $events
        );
        return $this->row(
            $points,
            sprintf(
                __('%1$d of %2$d events are published'),
                $published,
                $events
            ),
            __('Published events carry more weight than unpublished'
                . ' ones'),
            $context
        );
    }
}
