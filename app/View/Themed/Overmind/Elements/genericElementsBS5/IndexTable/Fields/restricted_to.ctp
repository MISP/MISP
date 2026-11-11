<?php
$raw = Hash::get($row, $field['data_path']);

$values = [];
if (is_array($raw)) {
    foreach ($raw as $v) {
        if ($v !== '' && $v !== null) {
            $values[] = (string)$v;
        }
    }
} elseif ($raw !== '' && $raw !== null) {
    // Accept a comma-separated requirement list packed into a single string.
    $values = preg_split('/\s*,\s*/', (string)$raw, -1, PREG_SPLIT_NO_EMPTY);
}

$isCard = isset($viewMode) && $viewMode === 'card';

if (empty($values)) {
    if ($isCard) {
        echo '<span class="text-muted">' . h($field['empty_label'] ?? __('No restriction')) . '</span>';
    } else {
        echo '<span class="text-muted">&mdash;</span>';
    }
    return;
}

$icon = $field['icon'] ?? 'fa-lock';
?>
<div class="d-inline-flex flex-wrap gap-1">
    <?php foreach ($values as $value): ?>
        <span class="badge bg-warning-subtle text-warning-emphasis border border-warning-subtle">
            <i class="fas <?= h($icon) ?> me-1"></i><?= h($value) ?>
        </span>
    <?php endforeach; ?>
</div>
