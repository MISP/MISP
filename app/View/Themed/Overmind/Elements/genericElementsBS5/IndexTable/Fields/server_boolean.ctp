<?php
$value = Hash::extract($row, $field['data_path']);
if (empty($value)) {
    return;
}

$boolean = !empty($field['boolean_reverse']) ? !$value[0] : $value[0];
$isCard = isset($viewMode) && $viewMode === 'card';
$trueLabel = $field['true'] ?? __('Enabled');
$falseLabel = $field['false'] ?? __('Disabled');
$label = $boolean ? $trueLabel : $falseLabel;
?>
<?php if ($isCard): ?>
    <span class="small <?= $boolean ? 'text-success' : 'text-secondary' ?>">
        <i class="fas <?= $boolean ? 'fa-check-circle' : 'fa-times-circle' ?> me-1"></i>
        <?= h($label) ?>
    </span>
<?php else: ?>
    <i
        class="fas <?= $boolean ? 'fa-check text-success' : 'fa-times text-secondary' ?>"
        title="<?= h($label) ?>"
        aria-label="<?= h($label) ?>"
    ></i>
<?php endif; ?>
