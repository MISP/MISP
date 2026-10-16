<?php
/**
 * The analyst-graph launcher on the rail. Kept current by intel-graph.js,
 * which also opens the dock on click.
 *
 * @var array $item
 */
$none = $item['count'] === null;
?>
<div class="rail-slot" data-intel-graph-slot data-state="<?= $none ? 'none' : 'active' ?>" title="<?= h($item['label'] . ($none ? '' : ' (' . $item['count'] . ')')) ?>"<?= empty($item['id']) ? '' : ' data-tour="nav-' . h($item['id']) . '"' ?>>
    <button type="button" class="rail-graph" data-intel-graph-toggle aria-label="<?= h($item['title']) ?>">
        <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
        <span class="rail-graph-name" data-intel-graph-name><?= h($item['label']) ?></span>
        <span class="rail-count" data-intel-graph-count<?= $none ? ' hidden' : '' ?>><?= h((string)$item['count']) ?></span>
    </button>
</div>
