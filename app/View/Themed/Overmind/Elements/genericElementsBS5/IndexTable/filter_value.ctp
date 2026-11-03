<?php
/**
 * One `value` child of the filter bar: a free-text, number or date filter
 * behind a picker button, its input the whole popover (index-filters.js).
 *
 * - name        : filter name, unprefixed
 * - label       : button and chip label
 * - icon        : classes of the button's icon
 * - input       : text (default), number or date
 * - placeholder : the input's
 * - step        : for a number input
 * - hint        : line under the input
 *
 * @var array $child
 * @var IndexFilterState $state
 */
$value = (string)($state->get($child['name']) ?? '');
$config = [
    'kind' => 'value',
    'name' => $child['name'],
    'label' => $child['label'],
    'input' => $child['input'] ?? 'text',
    'placeholder' => $child['placeholder'] ?? null,
    'step' => $child['step'] ?? null,
    'hint' => $child['hint'] ?? null,
    'value' => $value,
];
?>
<div class="ifp-picker flex-shrink-0" data-ifp-swap="picker-<?= h($child['name']) ?>" data-ifp-picker="<?= h(json_encode($config, JSON_UNESCAPED_UNICODE)) ?>">
    <button type="button" class="btn btn-sm btn-outline-secondary ifp-btn<?= $value !== '' ? ' is-set' : '' ?>" aria-expanded="false" aria-haspopup="dialog" data-tour="index-picker-<?= h($child['name']) ?>">
        <?php if (!empty($child['icon'])): ?>
            <i class="<?= h($child['icon']) ?>" aria-hidden="true"></i>
        <?php endif; ?>
        <span class="ifp-btn-label"><?= h($child['label']) ?></span>
        <?php if ($value !== ''): ?>
            <span class="badge rounded-pill bg-primary">1</span>
        <?php endif; ?>
        <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
    </button>
    <div class="ifp-pop" role="dialog" tabindex="-1" aria-label="<?= h($child['label']) ?>" hidden></div>
</div>
