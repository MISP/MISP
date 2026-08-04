<?php
/*
 * Expected:
 * $default (bool)
 * $full (bool) → Print label or just icon
 */

$default = isset($default) ? $default : false;
$full = $full ?? true;
?>

<div class="d-flex align-items-center">
    <?php if ($full): ?>
        <!-- CARD MODE -->
        <span class="badge default-color default-bg fw-semibold px-2 py-1">
            <?= $default ? __('Default') : __('Not default') ?>
        </span>

    <?php else: ?>
        <!-- TABLE MODE -->
        <i class="fas
            <?= $default ? 'fa-check default-color' : 'fa-minus default-color' ?>"
        style="font-size: 1.3em;"
        title="<?= $default ? __('Default') : __('Not default') ?>"
        aria-label="<?= $default ? __('Default') : __('Not default') ?>">
        </i>

    <?php endif; ?>
</div>