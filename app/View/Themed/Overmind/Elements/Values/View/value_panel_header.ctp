<?php
/**
 * The header strip every Value Intelligence panel wears: a tinted glyph tile,
 * a title, a subtitle carrying the panel's headline number, and room on
 * the right for the panel's own controls.
 *
 * Shared so the seven panels — and the not-yet-implemented ones sitting
 * between them — line up to the same 36px tile and the same baselines.
 *
 * @var string $panelTitle
 * @var string $panelIcon  Font Awesome class, or a full misp-icon triplet
 * @var string $panelColor CSS colour for the tile, a variable by intent
 * @var string $panelSub   Markup for the line under the title
 * @var string $panelNotes Markup under that line, aligned with the title
 * @var string $panelExtra Markup for the right-hand side
 */
$panelIcon = $panelIcon ?? 'fas fa-cube';
$panelColor = $panelColor ?? 'var(--bs-secondary-color)';
$panelSub = $panelSub ?? null;
$panelNotes = $panelNotes ?? null;
$panelExtra = $panelExtra ?? null;
$isMispGlyph = strpos($panelIcon, 'misp-icon') === 0;
?>
<div class="p-3 border-bottom d-flex gap-2 <?= $panelNotes === null
    ? 'align-items-center' : 'align-items-start' ?>">
    <span class="vp-panel-glyph">
        <?php if ($isMispGlyph): ?>
            <span class="<?= h($panelIcon) ?>"></span>
        <?php else: ?>
            <i class="<?= h($panelIcon) ?>"></i>
        <?php endif; ?>
    </span>
    <div class="me-auto vp-min-w-0 vp-panel-head-title">
        <div class="fw-bold lh-1"><?= h($panelTitle) ?></div>
        <?php if ($panelSub !== null): ?>
            <div class="small text-muted mt-1"><?= $panelSub ?></div>
        <?php endif; ?>
        <?php if ($panelNotes !== null): ?>
            <div class="vp-panel-head-notes"><?= $panelNotes ?></div>
        <?php endif; ?>
    </div>
    <?php if ($panelExtra !== null): ?>
        <div class="d-flex flex-wrap justify-content-end align-items-center
                    gap-2 vp-panel-head-extra">
            <?= $panelExtra ?>
        </div>
    <?php endif; ?>
</div>
