<?php
/*
 * domain_restrictions.ctp — renders an organisation's email-domain restrictions
 * as chips. Each domain is shown as an "@domain" badge; an empty restriction
 * list means the organisation is unrestricted.
 *
 * Field options:
 *   data_path => path to the value (array or newline/comma separated string)
 *   name      => used as the card label
 */
$domains = Hash::get($row, $field['data_path']);
$isCard  = isset($viewMode) && $viewMode === 'card';

if (!is_array($domains)) {
    $domains = preg_split('/[\r\n,]+/', trim((string)$domains), -1, PREG_SPLIT_NO_EMPTY);
}
$domains = array_values(array_filter(array_map('trim', $domains), function ($d) {
    return $d !== '';
}));
?>

<div class="d-flex flex-column gap-1">
    <?php if ($isCard && !empty($field['name'])): ?>
        <span class="text-muted small">
            <i class="fas fa-shield-halved me-1"></i><?= h($field['name']) ?>
        </span>
    <?php endif; ?>

    <?php if (empty($domains)): ?>
        <span class="badge text-bg-light border text-muted" style="width: fit-content;">
            <i class="fas fa-globe me-1"></i><?= __('Unrestricted') ?>
        </span>
    <?php else: ?>
        <div class="d-flex flex-wrap gap-1">
            <?php foreach ($domains as $domain): ?>
                <span class="badge text-bg-light border font-monospace" title="<?= h($domain) ?>">
                    <i class="fas fa-at me-1 text-muted"></i><?= h($domain) ?>
                </span>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
