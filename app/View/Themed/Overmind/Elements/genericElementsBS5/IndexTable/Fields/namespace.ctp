<?php

$namespace = Hash::extract($row, $field['data_path']);
$namespace = is_array($namespace) ? ($namespace[0] ?? null) : $namespace;

if (empty($namespace)) {
    echo '<span class="text-muted fst-italic small">' . __('No Namespace') . '</span>';
    return;
}
?>

<div class="d-inline-flex align-items-center">
    <div class="text-secondary-emphasis py-1 rounded-3 d-flex align-items-center shadow-xs">
        <i class="fas fa-folder-tree me-2 opacity-50"></i>
        <span class="fw-semibold fst-italic">
            <?= h($namespace) ?>
        </span>
    </div>
</div>