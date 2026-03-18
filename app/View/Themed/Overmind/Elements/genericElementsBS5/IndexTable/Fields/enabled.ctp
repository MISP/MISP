<?php
$value = Hash::get($row, $field['data_path']);
$isEnabled = !empty($value);
$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex align-items-center">
    <?php if ($isCard): ?>

        <!-- CARD MODE -->
        <span class="badge d-inline-flex align-items-center px-2 py-1 border 
            <?= $isEnabled ? 'border-success text-success' : 'border-danger text-danger' ?>">
            <i class="fas <?= $isEnabled ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?> me-1"></i>
            <?= $isEnabled ? __('Enabled') : __('Disabled') ?>
        </span>

    <?php else: ?>

        <!-- TABLE MODE -->
        <i class="fas
            <?= $isEnabled ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?>"
        style="font-size: 1.3em;"
        title="<?= $isEnabled ? __('Enabled') : __('Disabled') ?>"
        aria-label="<?= $isEnabled ? __('Enabled') : __('Disabled') ?>">
        </i>

    <?php endif; ?>
</div>