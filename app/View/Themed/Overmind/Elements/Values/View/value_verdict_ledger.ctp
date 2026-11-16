<?php
/**
 * The Assessment tab's signal strength card: how the score was built. One
 * block per family (reporting, sightings, attribution, lifecycle) headed by
 * what it asks and its net points, then each signal on a line with its
 * points and evidence; the date it holds as of is on hover. The signals sum
 * to the signal strength: what the record is worth, whatever it says about
 * the value.
 *
 * @var array $verdict
 */
App::uses('ValueBandReasonTool', 'Tools/ValueIntelligence');
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');

$ledger = $verdict['ledger'] ?? array();
$strength = $verdict['signal_strength'] ?? null;
$band = $verdict['band'] ?? 'none';

$count = 0;
foreach ($ledger as $group) {
    $count += count($group['signals']);
}
$signed = function ($points) {
    $points = (int)$points;
    return $points > 0 ? '+' . $points : ($points < 0 ? "\u{2212}" . abs($points) : "\u{00B1}0");
};
$tone = function ($points) {
    return (int)$points > 0 ? 'up' : ((int)$points < 0 ? 'down' : 'zero');
};

$figure = null;
if ($strength !== null && $band !== 'none') {
    $figure = '<span class="vp-card-figure">'
        . h(((int)$strength < 0 ? "\u{2212}" . abs((int)$strength) : (int)$strength) . ' / 100') . '</span>';
}
$weights = array(
    'user' => __('weights from your profile'),
    'org' => __('weights from your organisation\'s profile'),
    'shared' => __('weights from a shared profile'),
);
$sub = array();
if (!empty($ledger)) {
    $sub[] = sprintf(
        __('%1$s in %2$s'),
        __n('%s signal', '%s signals', $count, $count),
        __n('%s family', '%s families', count($ledger), count($ledger))
    );
    if (array_key_exists('profile_scope', $verdict)) {
        $sub[] = $weights[$verdict['profile_scope']] ?? __('weights from the instance default');
    }
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-vl" style="--vp-panel-color: var(--primary);">
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => $strength === null || $band === 'none'
            ? __('How the signal strength was built')
            : sprintf(__('How %s was built'), (int)$strength),
        'panelIcon' => 'fas fa-list-check',
        'panelColor' => 'var(--primary)',
        'panelSub' => empty($sub) ? null : '<span title="' . h((string)($verdict['composition_note'] ?? '')) . '">'
            . h(implode(' · ', $sub)) . '</span>',
        'panelExtra' => $figure,
    )) ?>

    <?php if (empty($ledger)): ?>
        <div class="p-3">
            <div class="vp-empty">
                <i class="fas fa-list-check" aria-hidden="true"></i>
                <span><?= __('No signal contributed to this assessment.') ?></span>
            </div>
        </div>
    <?php else: ?>
        <?php foreach ($ledger as $group): ?>
            <?php
            $net = 0;
            foreach ($group['signals'] as $signal) {
                $net += (int)$signal['contribution'];
            }
            ?>
            <div class="vp-vl-fam" style="--vp-fam: <?= h(ValueStatsTool::familyColour($group['kind'])) ?>;">
                <div class="vp-vl-fam-h">
                    <span class="vp-vl-fam-dot" aria-hidden="true"></span>
                    <span class="vp-vl-fam-n"><?= h($group['kind']) ?></span>
                    <?php if (!empty($group['note'])): ?>
                        <span class="vp-vl-fam-q"><?= h($group['note']) ?></span>
                    <?php endif; ?>
                    <span class="vp-vl-fam-t"><?= h($signed($net)) ?></span>
                </div>
                <?php foreach ($group['signals'] as $signal): ?>
                    <div class="vp-vl-sig"<?= empty($signal['as_of']) ? '' : ' title="' . h(sprintf(__('As of %s'), $signal['as_of'])) . '"' ?>>
                        <span class="vp-pts is-<?= h($tone($signal['contribution'])) ?>"><?= h($signed($signal['contribution'])) ?></span>
                        <span class="vp-vl-sig-body">
                            <?php if (empty($signal['tab'])): ?>
                                <span class="vp-vl-sig-t"><?= h($signal['signal']) ?></span>
                            <?php else: ?>
                                <a class="vp-vl-sig-t" href="#tab-<?= h($signal['tab']) ?>"
                                   title="<?= h(__('Open the tab holding this evidence')) ?>"><?= h($signal['signal']) ?></a>
                            <?php endif; ?>
                            <span class="vp-vl-sig-e"><?= h($signal['evidence']) ?></span>
                        </span>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>
        <?php $bandReason = ValueBandReasonTool::reasonFor($verdict); ?>
        <?php if ($bandReason !== null): ?>
            <div class="vp-vl-foot">
                <span><i class="fas fa-ruler-horizontal" aria-hidden="true"></i><?= h($bandReason) ?></span>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>
