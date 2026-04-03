<?php
$timestamp = Hash::extract($row, $field['data_path'])[0];

$mode = $field['mode'] ?? 'modified';
if ($mode === 'created' ) {
    $label = __('Created');
} else {
    $label = __('Last Modified');
}

$value = !empty($timestamp)
    ? $this->Time->time($timestamp)
    : __('N/A');

?>

<div class="d-flex align-items-center gap-1">

    <div class="text-muted small">
        <?= h($label) ?>
    </div>

    <div class="fw-semibold text-dark">
        <?= $value ?>
    </div>

</div>