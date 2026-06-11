<?php
$event = Hash::get($row, $field['data_path']);

$attrCount = (int)Hash::get($event, 'attribute_count', 0);
$corrCount = (int)Hash::get($event, 'correlation_count', 0);

// TODO: move styles to CSS and use classes instead of inline styles
$styleOrange = "background: linear-gradient(180deg, #f39c12 0%, #e67e22 50%, #d35400 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;";
?>

<div class="d-flex flex-column flex-wrap gap-2">

    <?php if ($attrCount !== 0): ?>
        <div class="d-inline-flex align-items-center fw-bold text-nowrap text-success">
            <span class="misp-icon misp-icon-attribute misp-simple misp-icon-md me-1"></span>
            <span><?= h($attrCount) ?> Attributes</span>
        </div>
    <?php endif; ?>

    <?php if ($corrCount !== 0): ?>
        <a class="d-inline-flex align-items-center fw-bold text-nowrap text-decoration-none text-warning" href="<?= $this->Html->url(['action' => 'view', $event['id']]) ?>/correlation:1">
            <i class="fas fa-link me-1"></i>
            <span><?= h($corrCount) ?> Correlations</span>
        </a>
    <?php endif; ?>

</div>