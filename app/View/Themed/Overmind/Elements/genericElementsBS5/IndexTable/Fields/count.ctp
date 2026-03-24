<?php
$value = Hash::get($row, $field['data_path']);

//Temp idea to do a different print depending the value
$badgeClass = 'bg-secondary';
if ($value > 0) {
    $badgeClass = 'bg-primary';
}
if ($value > 10) {
    $badgeClass = 'bg-success';
}
?>

<span class="badge <?= h($badgeClass) ?> rounded-pill px-3 py-2">
    <i class="fas fa-layer-group me-1"></i>
    <?= h($value) ?>
</span>