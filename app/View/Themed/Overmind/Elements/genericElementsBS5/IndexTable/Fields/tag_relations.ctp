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

$links = [
    [
        'count' => $eventCount,
        'class' => 'text-event',
        'icon' => 'misp-icon misp-icon-event misp-simple',
        'text' => 'Tagged Events',
        'url' => ['controller' => 'events', 'action' => 'index', 'searchtag' => $id],
    ],
    [
        'count' => $attrCount,
        'class' => 'text-attribute',
        'icon' => 'misp-icon misp-icon-attribute misp-simple',
        'text' => 'Tagged Attributes',
        'url' => ['controller' => 'attributes', 'action' => 'index', 'tags' => $id],
    ]
];
?>

<div class="d-flex <?= $isCard ? 'flex-wrap gap-3' : 'flex-column flex-wrap gap-2' ?>">
    <?php foreach ($links as $link): ?>
        <?php if ($link['count'] !== 0): ?>
            <a class="d-inline-flex align-items-center fw-bold text-nowrap text-decoration-none <?= $link['class'] ?>"
               href="<?= $this->Html->url($link['url']) ?>">
                <i class="<?= $link['icon'] ?> me-1"></i>
                <span><?= h($link['count']) ?> <?= $link['text'] ?></span>
            </a>
        <?php else: ?>
            <p class="d-inline-flex align-items-center fw-bold text-nowrap text-decoration-none mb-0 <?= $link['class'] ?>">
                <i class="<?= $link['icon'] ?> me-1"></i>
                <span><?= h($link['count']) ?> <?= $link['text'] ?></span>
            </p>
        <?php endif; ?>
    <?php endforeach; ?>
</div>