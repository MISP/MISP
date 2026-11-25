<?php
/*
 * The "⋯" menu a card header falls back to when its [data-card-actions] no
 * longer fit beside the title. Hidden until initCardActionOverflow() (in
 * mispOvermind.js) needs it; it fills itself from the real buttons on open.
 * Render it right after the [data-card-actions] container, in the same row.
 */
?>
<div class="dropdown d-none flex-shrink-0" data-card-actions-menu>
    <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="dropdown"
            data-bs-popper-config='{"strategy":"fixed"}' aria-expanded="false"
            title="<?= h(__('Actions')) ?>" aria-label="<?= h(__('Actions')) ?>">
        <i class="fas fa-ellipsis"></i>
    </button>
    <ul class="dropdown-menu dropdown-menu-end shadow-sm"></ul>
</div>
