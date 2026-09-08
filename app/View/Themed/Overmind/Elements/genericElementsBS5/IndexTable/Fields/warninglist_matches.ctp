<?php
/*
 * warninglist_matches.ctp
 *
 * Renders what a value search matched inside a warninglist: the entry of the
 * list that the searched value hit (e.g. 8.8.8.8 -> 8.8.8.0/24).
 *
 * Expected:
 * $field['data_path']      => path to [['value' => .., 'matched' => ..], ..]
 * $field['show_searched']  => also show the searched value (multi-value search)
 */

$matches = Hash::get($row, $field['data_path']) ?? [];

if (empty($matches)) {
    echo '<span class="text-muted">-</span>';
    return;
}

$showSearched = !empty($field['show_searched']);
?>

<div class="d-flex flex-wrap gap-1">
    <?php foreach ($matches as $match): ?>
        <span class="badge fw-semibold"
              style="background:transparent;color:var(--bs-warning);border:1px solid var(--bs-warning);">
            <?php if ($showSearched): ?>
                <span class="opacity-75"><?= h($match['value']) ?></span>
                <i class="fas fa-arrow-right mx-1 small"></i>
            <?php endif; ?>
            <?= h($match['matched']) ?>
        </span>
    <?php endforeach; ?>
</div>
