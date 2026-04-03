<?php
/*
 * Expected:
 * $enabled (bool)
 * $full (bool) → Print label or just icon
 */

$enabled = isset($enabled) ? $enabled : false;
$full = $full ?? true;
?>

<div class="d-flex align-items-center">
    <?php if ($full): ?>

        <!-- CARD MODE -->
        <span class="badge d-inline-flex align-items-center px-2 py-1 border 
            <?= $enabled ? 'border-success text-success' : 'border-danger text-danger' ?>">
            <i class="fas <?= $enabled ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?> me-1"></i>
            <?= $enabled ? __('Enabled') : __('Disabled') ?>
        </span>

    <?php else: ?>

        <!-- TABLE MODE -->
        <i class="fas
            <?= $enabled ? 'fa-check-circle text-success' : 'fa-times-circle text-danger' ?>"
        style="font-size: 1.3em;"
        title="<?= $enabled ? __('Enabled') : __('Disabled') ?>"
        aria-label="<?= $enabled ? __('Enabled') : __('Disabled') ?>">
        </i>

    <?php endif; ?>
</div>