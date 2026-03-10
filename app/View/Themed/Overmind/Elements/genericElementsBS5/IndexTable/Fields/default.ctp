<?php
$value = Hash::get($row, $field['data_path']);
$isDefault = !empty($value);
$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex align-items-center">
    <?php if ($isCard): ?>
        <!-- CARD MODE -->
        <span class="badge default-color default-bg fw-semibold px-3 py-2">
            <?= $isDefault ? __('Default') : __('Not default') ?>
        </span>

    <?php else: ?>
        <!-- TABLE MODE -->
        <i class="fas
            <?= $isDefault ? 'fa-check default-color' : 'fa-minus default-color' ?>"
        style="font-size: 1.3em;"
        title="<?= $isDefault ? __('Default') : __('Not default') ?>"
        aria-label="<?= $isDefault ? __('Default') : __('Not default') ?>">
        </i>

    <?php endif; ?>
</div>