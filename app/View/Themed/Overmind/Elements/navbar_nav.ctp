<?php
    // Stable hook for the onboarding tour, which spotlights the top-level
    // menus by name (nav-datapoints, nav-account, …).
    $tourAttr = empty($item['id'])
        ? ''
        : ' data-tour="nav-' . h($item['id']) . '"';
    $isActive = !empty($item['active']);
    $currentAttr = $isActive ? ' aria-current="true"' : '';
?>
<?php if (($item['type'] ?? null) === 'intelGraph'): ?>
    <?php // Kept current by intel-graph.js, which also opens the dock on click. ?>
    <li class="rc-slot rc-fluid" data-intel-graph-slot data-state="<?= $item['count'] === null ? 'none' : 'active' ?>" title="<?= h($item['label'] . ($item['count'] === null ? '' : ' (' . $item['count'] . ')')) ?>"<?= $tourAttr ?>>
        <button type="button" class="rc-chip" data-intel-graph-toggle aria-label="<?= h($item['title']) ?>">
            <?= $this->element('navbar_glyph', ['item' => $item]) ?>
            <span class="rc-chip-name" data-intel-graph-name><?= h($item['label']) ?></span>
            <span class="rc-count" data-intel-graph-count<?= $item['count'] === null ? ' hidden' : '' ?>><?= h((string)$item['count']) ?></span>
        </button>
    </li>
<?php elseif (!empty($item['children'])): ?>
    <?php $panelId = 'rc-p-' . h($item['id']); ?>
    <li class="rc-group<?= !empty($alignEnd) ? ' rc-end' : '' ?><?= $isActive ? ' is-active' : '' ?>"<?= $tourAttr ?>>
        <button type="button" class="rc-trigger" aria-expanded="false" aria-controls="<?= $panelId ?>"<?= $currentAttr ?><?= !empty($item['image']) ? ' title="' . h($item['label']) . '"' : '' ?>>
            <?= $this->element('navbar_glyph', ['item' => $item]) ?>
            <span class="rc-label<?= !empty($item['image']) ? ' rc-clip' : '' ?>"><?= h($item['label']) ?></span>
            <i class="rc-chev fas fa-chevron-down" aria-hidden="true"></i>
        </button>
        <ul class="rc-panel" id="<?= $panelId ?>">
            <?php foreach ($item['children'] as $i => $child): ?>
                <?= $this->element('navbar_item', ['item' => $child, 'subId' => $panelId . '-' . $i]) ?>
            <?php endforeach; ?>
        </ul>
    </li>
<?php else: ?>
    <li class="rc-group<?= $isActive ? ' is-active' : '' ?>"<?= $tourAttr ?>>
        <a class="rc-trigger" href="<?= h($item['url']) ?>"<?= $currentAttr ?>>
            <?= $this->element('navbar_glyph', ['item' => $item]) ?>
            <span class="rc-label"><?= h($item['label']) ?></span>
        </a>
    </li>
<?php endif; ?>
