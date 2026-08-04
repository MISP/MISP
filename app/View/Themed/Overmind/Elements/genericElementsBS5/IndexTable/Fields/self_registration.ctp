<?php
$selfRegistrationFlag = Hash::extract($row, $field['data_path_requirement']);
$isAllowed = !empty($selfRegistrationFlag[0]);

$baseUrl = Hash::extract($row, $field['data_path'])[0] ?? '';
?>

<div class="d-flex align-items-center gap-2">
    <?php if ($isAllowed): ?>
        <span class="badge bg-success-subtle text-success border border-success-subtle d-flex align-items-center px-2 py-1">
            <i class="fas fa-check-circle me-1"></i>
            <?= __('Enabled') ?>
        </span>

        <a href="<?= h($baseUrl) ?>/users/register" 
           class="btn btn-sm btn-outline-primary rounded-pill px-3 py-0 fw-bold shadow-sm text-nowrap"
           style="font-size: 0.75rem;">
            <i class="fas fa-user-plus me-1"></i>
            <?= __('Register') ?>
        </a>

    <?php else: ?>
        <span class="badge bg-secondary-subtle text-muted border border-secondary-subtle d-flex align-items-center px-2 py-1" 
              title="<?= __('Self-registration is not allowed for this instance') ?>" 
              data-bs-toggle="tooltip">
            <i class="fas fa-times-circle me-1"></i>
            <?= __('Disabled') ?>
        </span>
    <?php endif; ?>
</div>