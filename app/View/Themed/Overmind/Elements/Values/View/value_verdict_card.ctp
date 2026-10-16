<?php
/**
 * The assessment in one card: what the record asserts, and why.
 *
 * A summary of the Assessment tab, never a second opinion — the signals
 * here are the highest-weighted rows of the same ledger, and the count
 * of the ones that did not fit is stated rather than left implied. A
 * glass box with three sides showing is still a glass box; a black box
 * with a number in it is not.
 *
 * Lazily loaded into `.ajax-card` from
 * ValuesController::viewVerdictCard.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');

$verdict = $valueIntelligence['verdict'];

/*
 * The ledger is grouped by kind for the Assessment tab's benefit; the
 * card
 * wants the heaviest signals whatever kind they came from.
 */
$signals = array();
foreach ($verdict['ledger'] as $group) {
    foreach ($group['signals'] as $signal) {
        $signal['kind'] = $group['kind'];
        $signals[] = $signal;
    }
}
usort($signals, function ($a, $b) {
    return abs($b['contribution']) <=> abs($a['contribution']);
});
$top = array_slice($signals, 0, 3);
$rest = count($signals) - count($top);

/*
 * The profile that weighted this value, as a link to the page that
 * says what is in it — `view` for one the reader cannot change,
 * because the editor itself refuses an edit that is not theirs and
 * sending them there to be refused is worse than sending them to read
 * it. Plain text when the assessment names no profile id, which is
 * what a render that did not read one looks like.
 */
$weighting = h($verdict['profile']);
if (!empty($verdict['profile_id'])) {
    $weighting = $this->Html->link(
        $weighting,
        array(
            'controller' => 'analystProfiles',
            'action' => 'view',
            $verdict['profile_id'],
            '?' => empty($valueB64) ? array() : array('value' => $valueB64),
        ),
        array('escape' => false)
    );
}
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--primary);
            <?= h(ValueLean::directionStyle($verdict['lean'])) ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Assessment'),
        'panelIcon' => 'fas fa-gavel',
        'panelColor' => 'var(--primary)',
        'panelSub' => empty($verdict['ledger'])
            ? h(__('Nothing to weigh'))
            : sprintf(
                h(__('Analyst profile %s')),
                $weighting
            ),
    )) ?>

    <div class="p-3 d-flex flex-column gap-3">

        <?= $this->element('Values/View/value_verdict_axes', array(
            'verdict' => $verdict,
        )) ?>

        <?php if (empty($top)): ?>
            <?php /*
             * The prose only where there is prose. `ValueSummaryTool`
             * has written `summary` since 2026-09-13
             * (`10-wiring.md` §13), and this is the branch that
             * reaches it first, because a value with nothing to assess
             * has no signals to list instead. The guard stays: an
             * empty paragraph here would read as a card that failed
             * rather than one with nothing to say.
             */ ?>
            <?php if (!empty($verdict['summary'])): ?>
                <p class="vp-verdict-summary mb-0">
                    <?= h($verdict['summary']) ?>
                </p>
            <?php endif; ?>
        <?php else: ?>
            <div class="vp-signals">
                <?php foreach ($top as $signal):
                    $up = $signal['direction'] === 'up';
                    ?>
                    <div class="vp-signal<?= $up
                        ? ' vp-signal-up'
                        : ' vp-signal-down' ?>"
                         title="<?= h($signal['evidence']) ?>">
                        <span class="vp-signal-arrow">
                            <i class="fas fa-caret-<?=
                                $up ? 'up' : 'down' ?>"></i>
                        </span>
                        <span class="vp-signal-text">
                            <?= h($signal['signal']) ?>
                        </span>
                    </div>
                <?php endforeach; ?>
            </div>

            <?php if ($rest > 0): ?>
                <div class="vp-signals-rest">
                    <?= h(sprintf(
                        __('%s further signals not shown'),
                        $rest
                    )) ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>

        <?php /*
         * What would move this, borrowed from the tab's own aside and
         * drawn through its own element — three sentences on nearly
         * every value, built by `forVerdict` for every caller and
         * deleted here until now (`35-overview-borrowed.md` §5.3).
         *
         * It is under the signals because it answers the question they
         * raise: the ledger says what the record is, and these say what
         * would make it something else. The actions the aside draws
         * beneath them stay on the tab — they are writes this feature
         * does not do, and a disabled button is worse company for a
         * summary than no button at all.
         */ ?>
        <?php if (!empty($verdict['changers'])):
            /*
             * Two lines and a count, which is the grammar this card
             * already uses for the ledger above. All three cost 162px
             * in a rail column — the sentences name a threshold and a
             * band and wrap twice at this width — against the 100px
             * §5.3 budgeted, and a summary card that spends 162px
             * restating the tab is the thing phase 31 shortened this
             * column to stop.
             */
            $changers = array_slice($verdict['changers'], 0, 2);
            $changerRest = count($verdict['changers']) - count($changers);
            ?>
            <div>
                <div class="vp-subhead">
                    <?= __('What would change this') ?>
                </div>
                <div class="vp-changers">
                    <?= $this->element(
                        'Values/View/value_verdict_changer_rows',
                        array('changers' => $changers)
                    ) ?>
                    <?php if ($changerRest > 0): ?>
                        <div class="vp-signals-rest">
                            <?= h(sprintf(
                                __n(
                                    '%s further way to change this'
                                        . ' on the tab',
                                    '%s further ways to change this'
                                        . ' on the tab',
                                    $changerRest
                                ),
                                $changerRest
                            )) ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <a href="#tab-assessment"
           class="btn btn-sm btn-outline-primary w-100
                  d-flex align-items-center justify-content-center gap-1">
            <?= __('Full assessment') ?>
            <i class="fas fa-arrow-right"></i>
        </a>

    </div>

</div>
