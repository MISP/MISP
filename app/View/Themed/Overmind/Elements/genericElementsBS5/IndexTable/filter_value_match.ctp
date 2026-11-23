<?php
/**
 * A `value_match` child: a second free-text filter that must NOT be confused
 * with the index search. It lives in its own labelled dropdown, drives its
 * own named param and is applied explicitly (button / Enter), never on blur.
 *
 * @var array $child
 * @var string $value the current value, decoded
 * @var string $inputId
 * @var bool $picker whether index-filters.js drives the bar
 */
$active = $value !== '';
$buttonClass = $picker
    ? 'btn btn-sm btn-outline-secondary ifp-vm-btn' . ($active ? ' is-set' : '')
    : 'btn ' . ($active ? 'btn-primary' : 'btn-outline-primary');
?>
<div class="dropdown dropdown-filters flex-shrink-0"<?= $picker ? ' data-ifp-swap="vm-' . h($child['name']) . '"' : '' ?>>
    <button class="<?= $buttonClass ?> dropdown-toggle"
            type="button"
            data-bs-toggle="dropdown"
            data-bs-auto-close="outside"
            data-tour="index-value-match">
        <i class="<?= h($child['icon'] ?? 'fas fa-crosshairs') ?> me-1"></i>
        <span class="ifp-btn-label"><?= h($child['label'] ?? __('Search a value')) ?></span>
        <?php if ($picker): ?>
            <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
        <?php endif; ?>
    </button>

    <div class="dropdown-menu p-3" style="min-width: 26rem">
        <div class="input-group">
            <input
                id="<?= h($inputId) ?>"
                class="form-control topbar-filter value-match-input"
                type="text"
                name="<?= h($child['name']) ?>"
                data-manual="1"
                value="<?= h($value) ?>"
                placeholder="<?= h($child['placeholder'] ?? '') ?>"
            >
            <?php if ($active): ?>
                <button class="btn btn-outline-secondary value-match-clear"
                        type="button"
                        title="<?= __('Clear') ?>">
                    <i class="fas fa-times"></i>
                </button>
            <?php endif; ?>
            <button class="btn btn-primary value-match-apply" type="button">
                <i class="fas fa-search"></i>
            </button>
        </div>
        <?php if (!empty($child['hint'])): ?>
            <div class="form-text"><?= h($child['hint']) ?></div>
        <?php endif; ?>
    </div>
</div>
