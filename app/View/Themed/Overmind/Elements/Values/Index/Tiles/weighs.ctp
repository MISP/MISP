<?php
/**
 * What weighs a record.
 *
 * The method note says what the three axes *are*; this says how much
 * machinery is behind them. A reader meeting an assessment for the
 * first time has no sense of whether a signal-strength score is one rule of
 * thumb or a dozen independent readings, and the difference decides
 * how much weight they give it.
 *
 * **The three counts are the three things a profile declares**, in the
 * profile editor's own words: *Signals* weigh the record, *Exclusions*
 * drop evidence before any signal sees it, and *Conflict rules* — the
 * `escalations` key — can force a lean to `contested` when the record
 * contradicts itself too loudly for any lean to be honest.
 *
 * **Signals take the value slot** because they are what does the
 * weighing; the other two are qualifications on it. A tile for each
 * would claim the three are the same size of fact.
 *
 * It costs nothing: phase 7 resolved this profile and the resolution
 * is memoised, so all three are reads of an array already in memory.
 * The element is drawn only when a profile is in force — the caller
 * omits it otherwise, rather than drawing a *0 signals* tile beside a
 * strip that already says assessments carry no signal strength.
 *
 * @var array{signals: int, exclusions: int, escalations: int} $weighs
 */
?>
<div class="vi-tile" data-vi-tile="weighs">
    <div class="vi-tile__label"><i class="fas fa-scale-balanced vi-tile__icon" aria-hidden="true"></i><?= h(__('Scoring signals')) ?></div>
    <div class="vi-tile__value">
        <?= h(number_format($weighs['signals'])) ?>
    </div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__('%s in the active analyst profile, plus %s and %s.')),
        h(__n('signal', 'signals', $weighs['signals'])),
        '<b>' . h(number_format($weighs['exclusions'])) . '</b> ' . h(__n(
            'exclusion',
            'exclusions',
            $weighs['exclusions']
        )),
        '<b>' . h(number_format($weighs['escalations'])) . '</b> ' . h(__n(
            'conflict rule',
            'conflict rules',
            $weighs['escalations']
        ))
    ) ?></div>
</div>
