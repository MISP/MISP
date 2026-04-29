<?php
$organisation = Hash::get($row, 'Organisation', []);
$user = Hash::get($row, 'User', []);

if (empty($organisation) && empty($user)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';

$items = [];

// Organisation
if (!empty($organisation['name'])) {
    $items[] = [
        'type' => 'link',
        'url' => ['controller' => 'organisations', 'action' => 'view', $organisation['id']],
        'icon' => '<span class="fa fa-building text-primary"></span>',
        'text' => $organisation['name'],
        'is_org' => true,
        'org' => $organisation
    ];
}

// User
if (!empty($user['email'])) {
    $items[] = [
        'type' => 'text',
        'icon' => '<span class="fa fa-image-portrait text-muted"></span>',
        'text' => $user['email'],
        'is_org' => false
    ];
}
?>

<div class="d-flex <?= $isCard ? 'flex-wrap gap-3' : 'flex-column flex-wrap gap-2' ?>">
    <?php foreach ($items as $item): ?>
        <?php if ($item['type'] === 'link'): ?>
            <a class="d-flex align-items-center gap-2 text-decoration-none fw-semibold text-primary"
               href="<?= $this->Html->url($item['url']) ?>">
        <?php else: ?>
            <div class="d-flex align-items-center gap-1 fw-semibold">
        <?php endif; ?>

                <?= $item['icon'] ?>

                <?php if ($isCard): ?>
                    <span>Restricted to</span>
                <?php endif; ?>

                <?php if (!empty($item['is_org'])): ?>
                    <?= $this->OrgImg->getOrgLogoV2($item['org'], 20, false); ?>
                <?php endif; ?>

                <span><?= h($item['text']) ?></span>

        <?php if ($item['type'] === 'link'): ?>
            </a>
        <?php else: ?>
            </div>
        <?php endif; ?>
    <?php endforeach; ?>
</div>