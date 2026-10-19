<?php
/**
 * A side panel's button on the rail (side-panel.js).
 *
 * @var array $item
 */
?>
<div class="rail-slot rail-slot--panel" data-side-panel-slot="<?= h($item['panel']) ?>"<?= $item['count'] === null ? '' : ' data-has-count' ?> title="<?= h($item['title']) ?>"<?= empty($item['id']) ? '' : ' data-tour="nav-' . h($item['id']) . '"' ?>>
    <button type="button" class="rail-graph" data-side-panel-toggle="<?= h($item['panel']) ?>" aria-controls="<?= h($item['panel']) ?>" aria-expanded="false" aria-label="<?= h($item['title']) ?>">
        <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
        <span class="rail-graph-name"><?= h($item['label']) ?></span>
        <span class="rail-count" data-side-panel-count<?= $item['count'] === null ? ' hidden' : '' ?>><?= h((string)$item['count']) ?></span>
        <i class="fas fa-angles-left sp-slot-side" aria-hidden="true"></i>
    </button>
</div>
