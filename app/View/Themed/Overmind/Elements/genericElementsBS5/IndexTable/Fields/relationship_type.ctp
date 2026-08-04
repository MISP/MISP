<?php
/*
 * relationship_type.ctp
 *
 * Renders a galaxy cluster relationship type as a galaxy-coloured badge.
 *
 * Expected:
 * $field['data_path'] => path to the relationship type string.
 */
$type = Hash::get($row, $field['data_path']);

if (empty($type)) {
    echo '<span class="text-muted">-</span>';
    return;
}
?>
<span class="badge fw-semibold" style="background:rgba(139,92,246,.12);color:var(--bs-galaxy);">
    <i class="fas fa-arrow-right-long me-1"></i><?= h($type) ?>
</span>
