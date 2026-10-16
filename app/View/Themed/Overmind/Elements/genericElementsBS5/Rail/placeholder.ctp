<?php
/**
 * What a lazy rail card shows until it arrives: its real header and a
 * skeleton of its shape.
 *
 *   $card  array  a RailCard::slot()
 */
$skeletonLine = function ($short = false) {
    return '<div class="rcard-sk rcard-sk-line' . ($short ? ' rcard-sk-short' : '') . '"></div>';
};
?>
<section class="card shadow-sm mb-3 rcard-card rcard-loading rcard-shape-<?= h($card['shape']) ?>"
    aria-label="<?= h($card['title']) ?>" aria-busy="true">
    <div class="rcard-head p-3 border-bottom">
        <div class="rcard-tile rounded-2"><?= $this->RailCard->icon($card['icon']) ?></div>
        <div class="rcard-title fw-bold lh-1"><?= h($card['title']) ?></div>
    </div>
    <div class="rcard-body p-3">
        <div class="rcard-skeleton" role="status" aria-label="<?= h(__('Loading %s', $card['title'])) ?>">
            <?php if ($card['shape'] === 'activity'): ?>
                <div class="rcard-sk rcard-sk-num"></div>
                <div class="rcard-sk-bars">
                    <?php for ($i = 0; $i < 12; $i++): ?>
                        <span style="height: <?= 18 + (($i * 37) % 60) ?>%;"></span>
                    <?php endfor; ?>
                </div>
            <?php elseif ($card['shape'] === 'usage' || $card['shape'] === 'inventory'): ?>
                <div class="rcard-sk rcard-sk-num"></div>
                <div class="rcard-sk rcard-sk-bar"></div>
                <?= $skeletonLine() ?>
                <?= $skeletonLine(true) ?>
            <?php else: ?>
                <?php for ($i = 0; $i < 3; $i++): ?>
                    <div class="rcard-sk-row"><?= $skeletonLine() ?><?= $skeletonLine(true) ?></div>
                <?php endfor; ?>
            <?php endif; ?>
        </div>
    </div>
</section>
