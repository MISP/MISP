<?php
/**
 * Overmind theme override for the widget wrapper (PRD §8.3 Level 3).
 *
 * The default wrapper is `app/View/Elements/dashboard/widget/
 * wrapper.ctp` — Cake's Themed resolver picks this file instead when
 * `$this->theme = 'Overmind'`. Demonstrates that a heavy theme can
 * change *markup* (class names, element types, ordering, inner
 * structure) without breaking dashboard JS, because every
 * `data-misp-*` / `data-widget-*` / `data-drag-handle` /
 * `data-resize-handle` / `data-position-*` attribute is preserved.
 *
 * Visible differences from the default wrapper:
 *   - Outer element is a BS5-style `<div class="card">` (not <article>)
 *   - Title bar uses `.card-header` + flex utilities
 *   - Body uses `.card-body`
 *   - A small "Overmind" pill in the title bar makes the override
 *     obvious during prototype verification
 *
 * The styling for these classes ships at
 * `Themed/Overmind/webroot/css/dashboard/overmind.css`, loaded by
 * index.ctp when the Overmind theme is active.
 */
?>
<div class="card misp-widget--overmind"
     data-misp-widget
     data-widget-name="<?= h($widget['widget']) ?>"
     data-widget-instance-id="<?= h($widget['instance_id']) ?>"
     data-widget-config='<?= h(json_encode($widget['config'], JSON_UNESCAPED_SLASHES)) ?>'
     data-widget-schema='<?= h(json_encode(isset($widget['schema']) && is_array($widget['schema']) ? $widget['schema'] : array(), JSON_UNESCAPED_SLASHES)) ?>'
     data-widget-placeholder="<?= h(isset($widget['placeholder']) && is_string($widget['placeholder']) ? $widget['placeholder'] : '') ?>"
     <?php if (!empty($widget['alias'])): ?>data-widget-alias="<?= h($widget['alias']) ?>"<?php endif; ?>
     data-position-x="<?= h($widget['position']['x']) ?>"
     data-position-y="<?= h($widget['position']['y']) ?>"
     data-position-w="<?= h($widget['position']['w']) ?>"
     data-position-h="<?= h($widget['position']['h']) ?>">
    <div class="card-header d-flex align-items-center" data-drag-handle>
        <span class="card-title flex-grow-1 fw-medium mb-0">
            <?= h($widget['alias'] ?? $widget['widget']) ?>
            <span class="badge bg-primary misp-widget--overmind__badge" aria-label="<?= __('Overmind theme override active') ?>">Overmind</span>
        </span>
        <div class="btn-group btn-group-sm ms-2" role="group" aria-label="<?= __('Widget actions') ?>">
            <button type="button" class="btn btn-link btn-sm misp-widget--overmind__iconbtn"
                    data-misp-widget-action="refresh"
                    title="<?= __('Refresh') ?>" aria-label="<?= __('Refresh') ?>">↻</button>
            <button type="button" class="btn btn-link btn-sm misp-widget--overmind__iconbtn"
                    data-misp-widget-action="configure"
                    title="<?= __('Configure') ?>" aria-label="<?= __('Configure') ?>">⚙</button>
            <button type="button" class="btn btn-link btn-sm misp-widget--overmind__iconbtn misp-widget-iconbtn-edit-only"
                    data-misp-widget-action="remove"
                    title="<?= __('Remove') ?>" aria-label="<?= __('Remove') ?>">✕</button>
        </div>
    </div>
    <div class="card-body misp-widget--overmind__body" data-misp-widget-content>
        <div class="text-muted fst-italic text-center py-3"><?= __('Loading…') ?></div>
    </div>
    <span class="misp-widget--overmind__resize" data-resize-handle aria-hidden="true"></span>
</div>
