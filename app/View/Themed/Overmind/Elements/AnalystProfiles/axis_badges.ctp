<?php
/**
 * What a section or block moves, as one badge per axis: the lean in
 * its two readings, the relevance in its own hue, signal strength in
 * none — the value pages' palette — and what reaches no score drawn
 * apart. The title says what the axis is.
 *
 * @var array $axes From `AnalystProfileFormTool::axisBadges()`
 */
?>
<span class="ap-axes">
    <?php foreach ($axes as $axis): ?>
        <span class="ap-axis is-<?= h(str_replace('_', '-', $axis['key'])) ?>" title="<?= h($axis['title']) ?>">
            <?php if ($axis['key'] === 'lean'): ?>
                <i class="ap-axis-split" aria-hidden="true"></i>
            <?php elseif (!empty($axis['icon'])): ?>
                <i class="<?= $this->FontAwesome->getClass($axis['icon']) ?>" aria-hidden="true"></i>
            <?php endif; ?>
            <?= h($axis['label']) ?>
        </span>
    <?php endforeach; ?>
</span>
