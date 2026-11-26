<?php
/*
 * A template element's list of strings (values_list, categories) as chips.
 * The model decodes these JSON columns to a flat list.
 */
$values = Hash::get($row, $field['data_path']);
if (!is_array($values)) {
    $values = $values === null || $values === '' ? [] : [$values];
}
$values = array_values(array_filter($values, function ($value) {
    return is_scalar($value) && (string)$value !== '';
}));
if (empty($values)) {
    echo '<span class="text-body-secondary">&mdash;</span>';
    return;
}
?>
<div class="d-flex flex-wrap gap-1">
    <?php foreach ($values as $value): ?>
        <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal"><?= h($value) ?></span>
    <?php endforeach; ?>
</div>
