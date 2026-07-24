<?php
/*
 * datetime.ctp — renders a timestamp (unix int or parseable string).
 * Expected:
 *   $field['data_path'] => path to the value
 *   $field['empty']     => optional label when empty (default N/A)
 *   $field['name']      => in CARD view, prefixed as a muted label
 *                          (e.g. "Last login: 2026-…") so the value is explicit
 *                          without a column header.
 */
$value  = Hash::get($row, $field['data_path']);
$isCard = isset($viewMode) && $viewMode === 'card';

$formatted = is_numeric($value)
    ? date('Y-m-d H:i:s', (int)$value)
    : $value;
?>

<?php if ($isCard && !empty($field['name'])): ?>
    <div class="d-flex flex-column gap-1">
        <span class="text-muted small me-1">
            <?= h($field['name']) ?>
        </span>
        <?php if (empty($value)): ?>
            <span class="text-muted"> <?= h($field['empty'] ?? __('N/A')) ?> </span>
        <?php else: ?>
            <span class="fw-semibold"> <?= h($formatted) ?> </span>
        <?php endif; ?>
    </div>
<?php else: ?>
    <?php if (empty($value)): ?>
        <span class="text-muted"><?= h($field['empty'] ?? __('N/A')) ?></span>
    <?php else: ?>
        <span><?= h($formatted) ?></span>
    <?php endif; ?>
<?php endif; ?>
