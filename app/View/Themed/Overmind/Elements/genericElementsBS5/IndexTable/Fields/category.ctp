<?php
$category = Hash::extract($row, $field['data_path'])[0];

$isCard = isset($viewMode) && $viewMode === 'card';
?>
<div class="d-flex align-items-center text-nowrap">
    <p class="fst-italic mb-0"><?= $category ?></p>
    <?php if ($isCard): ?>
        <i class="fa-solid fa-chevron-right ms-1"></i>
    <?php endif; ?>
</div>
