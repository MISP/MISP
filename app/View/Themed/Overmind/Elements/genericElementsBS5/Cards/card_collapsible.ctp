<?php
$collapseId = !empty($id) ? h($id) : 'collapse-' . uniqid();

$isOpen = !isset($collapsed) || $collapsed === false;
$collapseClass = $isOpen ? 'collapse show' : 'collapse';
$expandedAttr = $isOpen ? 'true' : 'false';
$headerClass = $isOpen ? '' : 'collapsed';
$maxHeightStyle = !empty($maxHeight) ? 'max-height: ' . h($maxHeight) . '; overflow-y: auto;' : '';
?>

<div class="card shadow-sm mb-3">

    <?php if (!empty($title)): ?>
    <div class="card-header d-flex justify-content-between align-items-center <?= $headerClass ?>" 
         data-bs-toggle="collapse" 
         data-bs-target="#<?= $collapseId ?>" 
         aria-expanded="<?= $expandedAttr ?>" 
         aria-controls="<?= $collapseId ?>"
         style="cursor: pointer;">

        <div class="d-flex align-items-center fs-5">
            <?php if (!empty($icon)): ?>
            <i class="fas fa-<?= h($icon) ?> me-2 text-primary"></i>
            <?php endif; ?>
            <strong><?= h($title) ?></strong>
        </div>

        <i class="fas fa-chevron-up toggle-chevron text-secondary"></i>

    </div>
    <?php endif; ?>

    <div id="<?= $collapseId ?>" class="<?= $collapseClass ?>">
        <div class="card-body" style="<?= $maxHeightStyle ?>">
            <?= $content ?>
        </div>
    </div>

</div>