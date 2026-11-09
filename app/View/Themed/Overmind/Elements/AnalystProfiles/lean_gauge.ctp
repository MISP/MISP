<?php
/**
 * The lean's one number, drawn: the share of the reporting organisations
 * that must agree before a value leans, as a mark between contested and
 * leans, with what it comes to for a few sizes of reporting.
 *
 * @var array $block The thresholds section's `lean` block
 */
$share = null;
foreach ($block['fields'] as $field) {
    if ($field['key'] === 'lean_supermajority') {
        $share = $field['value'] ?? $field['default'] ?? null;
    }
}
if (!is_numeric($share)) {
    return;
}
$share = max(0, min(1, (float)$share));
$pct = round($share * 100, 1);
// The fewest that meet the share: a value at exactly the share leans.
$need = function ($reporters) use ($share) {
    return max(1, (int)ceil($share * $reporters - 1e-9));
};
?>
<div class="ap-lean">
    <div class="ap-lean-bar">
        <span class="ap-lean-zone is-split" style="width:<?= $pct ?>%"><?= h(__('contested')) ?></span>
        <span class="ap-lean-zone is-lean" style="width:<?= 100 - $pct ?>%"><?= h(__('leans')) ?></span>
        <span class="ap-lean-mark" style="left:<?= $pct ?>%"><b><?= h(round($share * 100)) ?>%</b></span>
    </div>
    <div class="ap-lean-scale">
        <span>0%</span>
        <span><?= h(__('of the reporting organisations agree')) ?></span>
        <span>100%</span>
    </div>
    <p class="ap-lean-eg">
        <span class="k"><?= h(__('Must agree')) ?></span>
        <?php foreach (array(2, 3, 4, 5, 10) as $reporters): ?>
            <span class="ap-lean-n"><b><?= h($need($reporters)) ?></b> <?= h(sprintf(__('of %s'), $reporters)) ?></span>
        <?php endforeach; ?>
    </p>
</div>
