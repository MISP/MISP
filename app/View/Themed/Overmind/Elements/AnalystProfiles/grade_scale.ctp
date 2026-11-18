<?php
/**
 * The Admiralty scale as a row of tiles: each grade's letter, what it
 * means and the multiplier it applies, with a bar against face value.
 * A multiplier is changed where it is read (inline_value.ctp).
 *
 * @var array $block The `org_trust_scale` fields block
 * @var bool $editable
 */
App::uses('AnalystProfileFormTool', 'Tools/AnalystProfile');

// The bar runs to the largest multiplier in force, never short of face value.
$top = 1.0;
foreach ($block['fields'] as $field) {
    $top = max($top, (float)($field['value'] ?? $field['default']));
}
$tone = function ($factor) {
    if ($factor <= 0) {
        return 'zero';
    }
    if (abs($factor - 1.0) < 0.001) {
        return 'flat';
    }
    return $factor > 1 ? 'up' : 'down';
};
?>
<div class="ap-live-head">
    <div class="ap-live-head-t"><?= $this->element('AnalystProfiles/block_head', array('block' => $block)) ?></div>
    <div class="ap-live-tools">
        <span class="ap-rules-sum"><?= h(empty($block['moved'])
            ? __('As shipped')
            : sprintf(__n('%d changed', '%d changed', $block['moved']), $block['moved'])) ?></span>
    </div>
</div>
<ol class="ap-grades">
    <?php foreach ($block['fields'] as $field): ?>
        <?php
        $factor = (float)($field['value'] ?? $field['default']);
        $changed = $field['value'] !== null && (float)$field['value'] !== (float)$field['default'];
        ?>
        <li class="ap-grade t-<?= h($tone($factor)) ?><?= $changed ? ' is-changed' : '' ?>"
            data-ap-unit="<?= h(implode('.', $field['path'])) ?>"<?=
            $editable ? ' data-ap-set="' . h(implode('.', $field['path'])) . '"' : '' ?>>
            <div class="ap-grade-h">
                <span class="ap-grade-badge" aria-hidden="true"><?= h($field['badge']) ?></span>
                <label class="ap-grade-m" for="<?= h(AnalystProfileFormTool::fieldId($field['path'])) ?>"><?=
                    h($field['meaning']) ?></label>
            </div>
            <span class="ap-grade-bar" aria-hidden="true">
                <i style="width: <?= h(round(min(1, $factor / $top) * 100, 1)) ?>%"></i>
                <b style="left: <?= h(round(1 / $top * 100, 1)) ?>%"></b>
            </span>
            <div class="ap-grade-v">
                <span class="ap-grade-x" aria-hidden="true">×</span>
                <?php if ($editable): ?>
                    <?= $this->element('AnalystProfiles/inline_value', array(
                        'field' => array('read_as' => number_format($factor, 2)) + $field,
                    )) ?>
                <?php else: ?>
                    <b><?= h(number_format($factor, 2)) ?></b>
                <?php endif; ?>
            </div>
            <?php if ($changed): ?>
                <span class="ap-grade-was"><?= h(sprintf(__('shipped ×%s'),
                    number_format((float)$field['default'], 2))) ?></span>
            <?php endif; ?>
        </li>
    <?php endforeach; ?>
</ol>
<p class="ap-grades-key">
    <span><i class="ap-grade-sw" aria-hidden="true"></i><?= h(__('face value, ×1.00')) ?></span>
    <span><?= h(__('A grade with no letter is a source nobody has graded.')) ?></span>
</p>
