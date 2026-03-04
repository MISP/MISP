<?php
$event = Hash::get($row, $field['data_path']);

$attrCount = (int)Hash::get($event, 'attribute_count', 0);
$corrCount = (int)Hash::get($event, 'correlation_count', 0);

// TODO: move styles to CSS and use classes instead of inline styles
$styleGreen = "background: linear-gradient(180deg, #2ecc71 0%, #27ae60 50%, #1e8449 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";
$styleOrange = "background: linear-gradient(180deg, #f39c12 0%, #e67e22 50%, #d35400 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";
?>

<div class="d-flex flex-column flex-wrap gap-2">

    <?php if ($attrCount !== 0): ?>
        <div class="d-inline-flex align-items-center fw-bold text-nowrap" style="<?= $styleGreen ?>">
            <i class="fas fa-inbox me-1"></i>
            <span><?= h($attrCount) ?> Attributes</span>
        </div>
    <?php endif; ?>

    <?php if ($corrCount !== 0): ?>
        <div class="d-inline-flex align-items-center fw-bold text-nowrap" style="<?= $styleOrange ?>">
            <i class="fas fa-link me-1"></i>
            <span><?= h($corrCount) ?> Correlations</span>
        </div>
    <?php endif; ?>

</div>