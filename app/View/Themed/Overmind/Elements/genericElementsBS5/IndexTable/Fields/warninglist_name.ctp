<?php
$object = Hash::extract($row, $field['data_path']);

if (empty($object)) {
    return;
}

$isCard = isset($viewMode) && $viewMode === 'card';
?>

<div class="d-flex flex-column gap-1">
    <div class="d-flex align-items-baseline gap-2 mb-0">
        <span class="fw-semibold"><?= $object['name'] ?></span>
    </div>

    <!-- Show if it contains a description -->
    <?php if (!empty($object['description'])): ?>
        <div class="card card-link-item" style="background-color: #f8f9fa;">
            <div class="card-body p-1">
                <i class="fa fa-comment"></i> 
                <span><?= h($object['description']) ?></span>
            </div>
        </div>
    <?php endif; ?>

</div>