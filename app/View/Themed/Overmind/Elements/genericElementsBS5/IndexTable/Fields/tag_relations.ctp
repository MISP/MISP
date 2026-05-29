<?php
$tag = Hash::get($row, $field['data_path']);

if (empty($tag)) {
    $paths = array_map('trim', explode(',', $field['data_path']));
    if (empty($paths)) {
        return;
    }
    $eventCount = Hash::extract($row, $paths[0])[0] ?? null;
    $attrCount = Hash::extract($row, $paths[1])[0] ?? null; 
    $id = Hash::extract($row, $paths[1])[0] ?? null; 
}
else {
    $eventCount = (int)Hash::get($tag, 'count', 0);
    $attrCount = (int)Hash::get($tag, 'attribute_count', 0);
    $id = (int)Hash::get($tag, 'id', 0);
}


$isCard = isset($viewMode) && $viewMode === 'card';

// TODO: move styles to CSS
$styleBlue = "background: linear-gradient(180deg, #43adc7 0%, #1892B1 50%, #106b81 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";
$styleGreen = "background: linear-gradient(180deg, #2ecc71 0%, #27ae60 50%, #1e8449 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";

$links = [
    [
        'count' => $eventCount,
        'style' => $styleBlue,
        'icon' => 'fas fa-clipboard-list',
        'text' => 'Tagged Events',
        'url' => ['controller' => 'events', 'action' => 'index', 'searchtag' => $id],
    ],
    [
        'count' => $attrCount,
        'style' => $styleGreen,
        'icon' => 'fas fa-inbox',
        'text' => 'Tagged Attributes',
        'url' => ['controller' => 'attributes', 'action' => 'index', 'tags' => $id],
    ]
];
?>

<div class="d-flex <?= $isCard ? 'flex-wrap gap-3' : 'flex-column flex-wrap gap-2' ?>">
    <?php foreach ($links as $link): ?>
        <?php if ($link['count'] !== 0): ?>
            <a class="d-inline-flex align-items-center fw-bold text-nowrap text-decoration-none"
               style="<?= $link['style'] ?>"
               href="<?= $this->Html->url($link['url']) ?>">
                <i class="<?= $link['icon'] ?> me-1"></i>
                <span><?= h($link['count']) ?> <?= $link['text'] ?></span>
            </a>
        <?php else: ?>
            <p class="d-inline-flex align-items-center fw-bold text-nowrap text-decoration-none mb-0"
               style="<?= $link['style'] ?>">
                <i class="<?= $link['icon'] ?> me-1"></i>
                <span><?= h($link['count']) ?> <?= $link['text'] ?></span>
            </p>
        <?php endif; ?>
    <?php endforeach; ?>
</div>