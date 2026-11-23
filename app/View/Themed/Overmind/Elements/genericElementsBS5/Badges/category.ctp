<?php
/*
 * Expected:
 * $category (string)
 * $full (bool) → Print label or just icon
 */

$category = isset($category) ? $category : null;
$full = $full ?? true;
?>


<div class="d-flex align-items-center text-nowrap">
    <p class="om-category mb-0"><?= h($category) ?></p>
    <?php if ($full): ?>
        <i class="fa-solid fa-chevron-right ms-1"></i>
    <?php endif; ?>
</div>