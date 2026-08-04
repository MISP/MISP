<?php
/*
 * synonyms.ctp
 *
 * Renders a list of synonyms as dashed-border badges
 *
 * Expected:
 * $data_path => path to an array of synonym strings
 * $field['limit'] => optional max badges to show (default 8)
 */
$syns = Hash::get($row, $field['data_path']) ?? [];

if (empty($syns)) {
    echo '<span class="text-muted">-</span>';
    return;
}

$limit = $field['limit'] ?? 8;
$shown = array_slice($syns, 0, $limit);
?>

<div class="d-flex flex-wrap gap-1">
    <?php foreach ($shown as $s): ?>
        <span class="badge fw-semibold"
              style="background:transparent;color:var(--bs-primary);border:1px dashed var(--bs-primary);">
            <?= h($s) ?>
        </span>
    <?php endforeach; ?>
    <?php if (count($syns) > $limit): ?>
        <span class="text-muted small align-self-center">+<?= count($syns) - $limit ?></span>
    <?php endif; ?>
</div>
