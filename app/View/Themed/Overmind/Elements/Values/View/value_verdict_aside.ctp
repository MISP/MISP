<?php
/**
 * The Assessment tab's right rail.
 *
 * The split between this and the main column is by what each section
 * needs, not by importance: the evidence — the ledger grid, the
 * occurrence tables, the two cases side by side — needs horizontal
 * room and stays wide. What sits here is either a self-contained
 * summary or a reference fact, and it is more useful beside the
 * evidence than below it.
 *
 * Which cards appear is a property of the value, the same way the main
 * column's layout is. A contested value has no single signal strength to
 * compose, and an agreeing one has no warninglist hit to explain.
 *
 * Lazily loaded into `.ajax-card` from
 * ValuesController::viewVerdictAside.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$verdict = $valueIntelligence['verdict'];
/*
 * The same predicate `ValuesController::viewVerdict` picks the main
 * column's template with. Read its docblock before changing either:
 * the rail and the tab are separate requests, and a lean test here
 * that disagrees with the one there puts a contested rail beside an
 * agreeing argument.
 */
$conflicted = ValueLean::hasConflictedLayout($verdict);

$uid = 'vp' . substr(md5($valueIntelligence['value'] . '-aside'), 0, 8);

/*
 * A `none` lean has none of these, so the rail renders nothing
 * rather than a column of empty states — the main column already says
 * that no signal was found, and saying it four more times narrower
 * would not make it truer.
 */
/*
 * Resolve it leads the conflicted rail. It is the only card on the page
 * that asks the reader to do something, and the argument beside it
 * exists to inform that choice — so it sits where the eye lands first,
 * not below three cards of evidence.
 */
$cards = $conflicted
    ? array(
        array('element' => 'value_verdict_resolve'),
        array('element' => 'value_verdict_case_composition'),
        array('element' => 'value_verdict_opinions'),
        array(
            'element' => 'value_verdict_curves',
            'chart' => 'curves',
            'title' => __('Shelf life'),
        ),
        array('element' => 'value_verdict_not_counted'),
    )
    : array(
        array('element' => 'value_verdict_composition'),
        /*
         * *Shelf life*, not *Verdict over time*, since phase 9. There
         * is no verdict over time to draw — the page computes at render
         * and stores nothing, so there is no yesterday's score to plot
         * — and what the card draws now is the relevance runway, which
         * is reconstructed from dates and therefore has a real history.
         * `ValueIntelligence::verdictCurves` carries the whole argument.
         */
        array(
            'element' => 'value_verdict_curves',
            'chart' => 'curves',
            'title' => __('Shelf life'),
        ),
        array('element' => 'value_verdict_not_counted'),
        array('element' => 'value_verdict_changers'),
    );

$noWrites = __(
    'Disabled in this pass — the Value Intelligence page does not write to'
    . ' the database yet.'
);

foreach ($cards as $card) {
    $params = array(
        'valueIntelligence' => $valueIntelligence,
        'noWrites' => $noWrites,
    );
    if (!empty($card['chart'])) {
        $params['chartId'] = $uid . '-' . $card['chart'];
    }
    if (!empty($card['title'])) {
        $params['cardTitle'] = $card['title'];
    }
    echo $this->element(
        'Values/View/' . $card['element'],
        $params
    );
}
