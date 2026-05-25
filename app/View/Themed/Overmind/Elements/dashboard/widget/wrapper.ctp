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
 *
 * The styling for these classes ships at
 * `Themed/Overmind/webroot/css/dashboard/overmind.css`, loaded by
 * `Themed/Overmind/Layouts/dashboard.ctp` via the standard css
 * array entry `'dashboard/overmind'`. Cake's `Helper::webroot()`
 * is theme-aware: when `$this->theme === 'Overmind'`, it falls
 * back to `App::themePath('Overmind')/webroot/<path>` and emits a
 * `/theme/Overmind/<path>` URL. No dot-prefix needed (the
 * `Theme.path` dot-notation would be interpreted as a plugin
 * namespace by `pluginSplit` and produce a 404).
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
     <?php if (!empty($widget['autoRefreshDelay']) && (int)$widget['autoRefreshDelay'] > 0): ?>data-widget-refresh-delay="<?= (int)$widget['autoRefreshDelay'] ?>"<?php endif; ?>
     data-position-x="<?= h($widget['position']['x']) ?>"
     data-position-y="<?= h($widget['position']['y']) ?>"
     data-position-w="<?= h($widget['position']['w']) ?>"
     data-position-h="<?= h($widget['position']['h']) ?>">
    <div class="card-header d-flex align-items-center" data-drag-handle>
        <span class="card-title flex-grow-1 fw-medium mb-0">
            <?= h($widget['alias'] ?? $widget['widget']) ?>
        </span>
        <span class="misp-widget-refresh-indicator misp-widget--overmind__refresh-indicator text-muted small me-2"
              data-misp-widget-refresh-indicator
              aria-live="polite"
              aria-atomic="true"></span>
        <div class="btn-group btn-group-sm ms-2" role="group" aria-label="<?= __('Widget actions') ?>">
            <button type="button" class="btn btn-link btn-sm misp-widget--overmind__iconbtn"
                    data-misp-widget-action="refresh"
                    title="<?= __('Refresh') ?>" aria-label="<?= __('Refresh') ?>">↻</button>
            <button type="button" class="btn btn-link btn-sm misp-widget--overmind__iconbtn"
                    data-misp-widget-action="configure"
                    title="<?= __('Configure') ?>" aria-label="<?= __('Configure') ?>">⚙</button>
            <span class="misp-widget-export misp-widget--overmind__export" data-misp-menubutton>
                <button type="button" class="btn btn-link btn-sm misp-widget--overmind__iconbtn"
                        data-misp-menubutton-trigger aria-haspopup="menu" aria-expanded="false"
                        title="<?= __('Export raw data') ?>" aria-label="<?= __('Export raw data') ?>">⬇</button>
                <span class="misp-widget-menu misp-widget--overmind__menu" role="menu" data-misp-menubutton-menu hidden>
                    <button type="button" class="misp-widget-menuitem misp-widget--overmind__menuitem" role="menuitem" data-misp-widget-action="export-json"><?= __('Export as JSON') ?></button>
                    <button type="button" class="misp-widget-menuitem misp-widget--overmind__menuitem" role="menuitem" data-misp-widget-action="export-csv"><?= __('Export as CSV') ?></button>
                </span>
            </span>
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
