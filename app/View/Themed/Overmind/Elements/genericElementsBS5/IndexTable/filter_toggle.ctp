<?php
/*
 * The "More filters" button: opens the panel `filter_panel` renders, and
 * carries the count of everything currently filtering.
 *
 * The count is NOT just the panel's own controls — a search term or a scope
 * set from elsewhere stays invisible once the panel is folded, so the badge
 * is the only thing left saying anything is on. initIndexFilterDraft()
 * recomputes it on every change; this is the first paint.
 *
 * Parameters:
 *  - $target : id of the collapse to toggle (no '#')
 *  - $count  : how many filters are active
 *  - $open   : whether the panel starts expanded
 *  - $label  : button text (default "More Filters")
 */
$label = $label ?? __('More Filters');
?>
<button type="button"
        class="btn btn-outline-primary dropdown-toggle flex-shrink-0"
        data-bs-toggle="collapse"
        data-bs-target="#<?= h($target) ?>"
        aria-expanded="<?= !empty($open) ? 'true' : 'false' ?>">
    <i class="fas fa-sliders-h me-1"></i><?= h($label) ?>
    <span class="badge bg-primary ms-1 filter-draft-count <?= !empty($count) ? '' : 'd-none' ?>"><?= (int)$count ?></span>
</button>
