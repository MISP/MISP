<?php
$value = Hash::get($row, $field['data_path']);

$displayMode = $field['display'] ?? 'long';

?>

<div class="d-flex align-items-center">
    <?php if (!empty($value)): ?>
        <?php if ($displayMode === 'long'): ?>
            <span class="badge bg-success me-2"><?= __('Published') ?></span>
        <?php else: ?>
            <span class="fas fa-check-circle text-success" style="font-size: 1.5em;" title="<?= __('Published') ?>" aria-label="<?= __('Published') ?>">
        <?php endif; ?>
    <?php else: ?>
        <?php if ($displayMode === 'long'): ?>
            <span class="badge bg-danger me-2"><?= __('Unpublished') ?></span>
        <?php else: ?>
            <span class="fas fa-times-circle text-danger" style="font-size: 1.5em;" title="<?= __('Unpublished') ?>" aria-label="<?= __('Unpublished') ?>">
        <?php endif; ?>
    <?php endif; ?>
    </span>
</div>