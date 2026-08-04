<?php
/*
 * labeled_text.ctp — a plain text value with a light visual treatment.
 *   TABLE view: the value prefixed by an optional muted icon.
 *   CARD  view: a muted small label (the field name) above the value — mirrors
 *               the card layout of datetime.ctp so meta rows read consistently.
 *
 * Field options:
 *   data_path => path to the value
 *   name      => used as the card label
 *   icon      => optional Font Awesome icon name without the "fa-" prefix
 *                (e.g. 'industry', 'address-book', 'user-plus')
 *   empty     => fallback label when the value is empty (default N/A)
 */
$value  = Hash::get($row, $field['data_path']);
if (is_array($value)) {
    $value = implode(', ', $value);
}
$value  = is_string($value) ? trim($value) : $value;
$isCard = isset($viewMode) && $viewMode === 'card';
$icon   = $field['icon'] ?? null;
$empty  = $field['empty'] ?? __('N/A');
$hasValue = !($value === null || $value === '');
?>

<?php if ($isCard): ?>
    <div class="d-flex flex-column gap-1">
        <?php if (!empty($field['name'])): ?>
            <span class="text-muted small">
                <?php if ($icon): ?><i class="fas fa-<?= h($icon) ?> me-1"></i><?php endif; ?>
                <?= h($field['name']) ?>
            </span>
        <?php endif; ?>
        <?php if ($hasValue): ?>
            <span class="fw-semibold"><?= nl2br(h($value)) ?></span>
        <?php else: ?>
            <span class="text-muted"><?= h($empty) ?></span>
        <?php endif; ?>
    </div>
<?php else: ?>
    <?php if ($hasValue): ?>
        <span class="d-inline-flex align-items-center gap-1">
            <?php if ($icon): ?><i class="fas fa-<?= h($icon) ?> text-muted"></i><?php endif; ?>
            <span><?= nl2br(h($value)) ?></span>
        </span>
    <?php else: ?>
        <span class="text-muted">&mdash;</span>
    <?php endif; ?>
<?php endif; ?>
