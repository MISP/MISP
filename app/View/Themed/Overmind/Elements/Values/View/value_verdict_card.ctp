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
 * The profile that weighted this value, linking to the page that says
 * what is in it. Plain text when the assessment names no profile id.
 */
$weighting = h($verdict['profile']);
if (!empty($verdict['profile_id'])) {
    $weighting = $this->Html->link(
        $weighting,
        array(
            'controller' => 'analystProfiles',
            'action' => 'view',
            $verdict['profile_id'],
            '?' => array('value' => $valueIntelligence['value']),
        ),
        array('escape' => false, 'title' => __('Open your analyst profile'))
    );
}

$tabLink = '<a class="vp-head-link" href="#tab-assessment">'
    . h(__('Full assessment'))
    . ' <i class="fas fa-arrow-right" aria-hidden="true"></i></a>';
$subtitle = empty($verdict['ledger'])
    ? h(__('Nothing to weigh')) . ' &nbsp;·&nbsp; ' . $tabLink
    : $tabLink;
?>
<div class="card shadow-sm mb-3 vp-panel vp-verdict-card"
     style="--vp-panel-color: var(--primary);
            <?= h(ValueLean::directionStyle($verdict['lean'])) ?>">

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Assessment'),
        'panelIcon' => 'fas fa-gavel',
        'panelColor' => 'var(--primary)',
        'panelSub' => $subtitle,
    )) ?>

    <div class="p-3 d-flex flex-column gap-3">

        <?= $this->element('Values/View/value_verdict_axes', array(
            'verdict' => $verdict,
        )) ?>

        <?php if (empty($top)): ?>
            <?php if (!empty($verdict['summary'])): ?>
                <p class="vp-verdict-summary mb-0">
                    <?= h($verdict['summary']) ?>
                </p>
            <?php endif; ?>
        <?php else: ?>
            <div>
                <div class="vp-subhead"><?= __('Strongest signals') ?></div>
                <?php // The ledger's heaviest rows, drawn as the tab draws them. ?>
                <div class="vp-sigs">
                    <?php foreach ($top as $signal):
                        $up = $signal['direction'] === 'up';
                        $points = (int)$signal['contribution'];
                        ?>
                        <div class="vp-sig vp-ledger-line<?= $up
                            ? ' vp-ledger-line-up'
                            : ' vp-ledger-line-down' ?>">
                            <span class="vp-ledger-dir" aria-hidden="true"><?=
                                $up ? '&#9650;' : '&#9660;' ?></span>
                            <span class="vp-sig-name">
                                <?php if (empty($signal['tab'])): ?>
                                    <?= h($signal['signal']) ?>
                                <?php else: ?>
                                    <a class="vp-ledger-signal-link"
                                       href="#tab-<?= h($signal['tab']) ?>"
                                       title="<?= h(__('Open the tab holding this evidence')) ?>"><?=
                                        h($signal['signal']) ?></a>
                                <?php endif; ?>
                            </span>
                            <span class="vp-ledger-points"
                                  title="<?= h(sprintf(__('%s points'), $points)) ?>"><?=
                                h(($points > 0 ? '+' : '') . $points) ?></span>
                            <?php if (!empty($signal['evidence'])): ?>
                                <span class="vp-sig-evidence"
                                      title="<?= h($signal['evidence']) ?>"><?=
                                    h($signal['evidence']) ?></span>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
                <?php if ($rest > 0): ?>
                    <div class="vp-sigs-rest">
                        <?= h(sprintf(
                            __n(
                                '%s more signal in the full assessment',
                                '%s more signals in the full assessment',
                                $rest
                            ),
                            $rest
                        )) ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($verdict['changers'])):
            // Two lines and a count; the rest are on the tab.
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
                        <div class="vp-sigs-rest">
                            <?= h(sprintf(
                                __n(
                                    '%s more in the full assessment',
                                    '%s more in the full assessment',
                                    $changerRest
                                ),
                                $changerRest
                            )) ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

    </div>

    <?php if (!empty($verdict['profile'])): ?>
        <?php // As the event overview's Context card says which profile it reads through. ?>
        <div class="eo-card-foot">
            <span class="eo-profile"
                  title="<?= h(__('Its weights score this assessment.')) ?>">
                <i class="fas fa-user-gear"></i>
                <span><?= __('Seen through your %s analyst profile', $weighting) ?></span>
                <a href="<?= h($baseurl . '/analystProfiles/index') ?>"
                   class="eo-profile-change"
                   title="<?= h(__('Change profile')) ?>"
                   aria-label="<?= h(__('Change profile')) ?>"><i class="fas fa-sliders"></i></a>
            </span>
        </div>
    <?php endif; ?>

</div>
