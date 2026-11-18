<?php
/**
 * The assessment's two actions, as icons at the end of its provenance line.
 * Both are disabled for now and say why in their title.
 */
?>
<span class="vp-verdict-meta-actions">
    <button type="button" class="vp-verdict-act" disabled
            title="<?= h(__('Recompute') . ' — ' . __('Not available yet: this page does not write to the database.')) ?>"
            aria-label="<?= h(__('Recompute')) ?>">
        <i class="fas fa-rotate" aria-hidden="true"></i>
    </button>
    <button type="button" class="vp-verdict-act is-mono" disabled
            title="<?= h(__('View as JSON') . ' — ' . __('Not available yet: the assessment has no API representation.')) ?>"
            aria-label="<?= h(__('View as JSON')) ?>">{ }</button>
</span>
