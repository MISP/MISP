<?php
/**
 * The search line over a Collaboration rail card's entries, drawn once the
 * card holds enough of them to need one. value-intelligence.js narrows the
 * card's [data-vp-entry] on input.
 *
 * @var int $count
 * @var string $placeholder
 */
if ($count < 4) {
    return;
}
?>
<div class="vp-entries-search">
    <div class="input-group input-group-sm">
        <span class="input-group-text border-end-0"><i class="fas fa-search text-muted small" aria-hidden="true"></i></span>
        <input type="search" class="form-control border-start-0 ps-0" data-vp-entries-filter autocomplete="off"
               placeholder="<?= h($placeholder) ?>" aria-label="<?= h($placeholder) ?>">
    </div>
</div>
