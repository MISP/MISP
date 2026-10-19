<?php
/**
 * The News button on the rail. news-panel.js opens the panel on click and
 * clears the count once the news are read.
 *
 * @var array $item
 */
?>
<div class="rail-slot rail-slot--news" data-news-slot data-state="<?= $item['count'] === null ? 'read' : 'unread' ?>" title="<?= h($item['title']) ?>"<?= empty($item['id']) ? '' : ' data-tour="nav-' . h($item['id']) . '"' ?>>
    <button type="button" class="rail-graph" data-news-toggle aria-controls="nw-so" aria-expanded="false" aria-label="<?= h($item['title']) ?>">
        <?= $this->element('navbar_rail_glyph', ['item' => $item]) ?>
        <span class="rail-graph-name"><?= h($item['label']) ?></span>
        <span class="rail-count" data-news-count<?= $item['count'] === null ? ' hidden' : '' ?>><?= h((string)$item['count']) ?></span>
        <i class="fas fa-angles-left nw-slot-side" aria-hidden="true"></i>
    </button>
</div>
