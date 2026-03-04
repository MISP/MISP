<?php
$value = Hash::get($row, $field['data_path']);
$isPublished = !empty($value);
$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex align-items-center">
    <?php if ($isCard): ?>

        <!-- CARD MODE -->
        <span class="badge d-inline-flex align-items-center px-2 py-1 border 
            <?= $isPublished ? 'border-success text-success' : 'border-danger text-danger' ?>">
            <i class="fas <?= $isPublished ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?> me-1"></i>
            <?= $isPublished ? __('Published') : __('Unpublished') ?>
        </span>

    <?php else: ?>

        <!-- TABLE MODE -->
        <i class="fas
            <?= $isPublished ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?>"
        style="font-size: 1.3em;"
        title="<?= $isPublished ? __('Published') : __('Unpublished') ?>"
        aria-label="<?= $isPublished ? __('Published') : __('Unpublished') ?>">
        </i>

    <?php endif; ?>
</div>