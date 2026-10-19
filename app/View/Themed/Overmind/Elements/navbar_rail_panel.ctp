<?php
/**
 * A side panel's button on the rail (side-panel.js): its icon alone on the
 * bar, lit while there is something for the user there. The name shows in the
 * phone drawer.
 *
 * @var array $item
 */
?>
<div class="rail-slot rail-slot--panel" data-side-panel-slot="<?= h($item['panel']) ?>" data-state="<?= empty($item['lit']) ? 'none' : 'active' ?>"<?= empty($item['home']) ? '' : ' data-home' ?> title="<?= h($item['title']) ?>"<?= empty($item['id']) ? '' : ' data-tour="nav-' . h($item['id']) . '"' ?>>
    <button type="button" class="rail-graph" data-side-panel-toggle="<?= h($item['panel']) ?>" aria-controls="<?= h($item['panel']) ?>" aria-expanded="false" aria-label="<?= h($item['title']) ?>">
        <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
        <span class="rail-graph-name"><?= h($item['label']) ?></span>
        <span class="rail-count" data-side-panel-count<?= $item['count'] === null ? ' hidden' : '' ?>><?= h((string)$item['count']) ?></span>
    </button>
</div>
