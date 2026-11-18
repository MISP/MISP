<?php
/**
 * The Assessment tab's signal strength card: how the score was built. One
 * block per family (reporting, sightings, attribution, lifecycle) headed by
 * what it asks and its net points, then each signal on a line with its
 * points and evidence, heaviest first, the points sized by their share of
 * the score; the date it holds as of is on hover. The signals sum
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
$moved = 0;
foreach ($ledger as $i => $group) {
    $count += count($group['signals']);
    foreach ($group['signals'] as $signal) {
        $moved += abs((int)$signal['contribution']);
    }
    // The heaviest signals lead their family.
    usort($ledger[$i]['signals'], function ($a, $b) {
        return abs((int)$b['contribution']) <=> abs((int)$a['contribution']);
    });
}
$signed = function ($points) {
    $points = (int)$points;
    return $points > 0 ? '+' . $points : ($points < 0 ? "\u{2212}" . abs($points) : "\u{00B1}0");
};
$tone = function ($points) {
    return (int)$points > 0 ? 'up' : ((int)$points < 0 ? 'down' : 'zero');
};
// A signal's share of all the points moved, either way: a fifth or more
// stands out, a point or under 5% recedes.
$share = function ($points) use ($moved) {
    return $moved > 0 ? abs((int)$points) / $moved : 0;
};
$weight = function ($points) use ($share) {
    if (abs((int)$points) <= 1 || $share($points) < 0.05) {
        return ' is-minor';
    }
    return $share($points) >= 0.2 ? ' is-major' : '';
};

$figure = null;
$score = (int)$strength < 0 ? "\u{2212}" . abs((int)$strength) : (string)(int)$strength;
if ($strength !== null && $band !== 'none') {
    $figure = '<span class="vp-card-figure">' . h($score . ' / 100') . '</span>';
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
            : sprintf(__('How %s was built'), $score),
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
                        <span class="vp-pts is-<?= h($tone($signal['contribution'])) . $weight($signal['contribution']) ?>"
                              title="<?= h(sprintf(__('%s%% of the points behind this score'), (int)round($share($signal['contribution']) * 100))) ?>"><?= h($signed($signal['contribution'])) ?></span>
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
