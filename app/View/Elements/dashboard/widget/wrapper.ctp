<?php
/**
 * Default widget wrapper (PRD §8.3 override surface).
 *
 * Per the stable §8.5 hook contract, this template MUST keep every
 * `data-*` attribute the BoardModule / GridModule / ConfigureModule /
 * ToolbarModule depend on:
 *
 *   data-misp-widget                 — widget root marker
 *   data-widget-name                 — class name for AJAX render
 *   data-widget-instance-id          — stable instance id
 *   data-widget-config               — JSON-encoded config
 *   data-widget-schema               — JSON-encoded $schema (PRD §5.7)
 *   data-widget-placeholder          — raw $placeholder string (DD-06 seed)
 *   data-widget-title                — widget's human-readable name
 *                                      ($title); client title fallback
 *                                      when config.alias is blank (DD-18)
 *   data-widget-refresh-delay        — Phase 5 board-level scheduler tick
 *                                      (seconds; only emitted when > 0)
 *   data-position-{x,y,w,h}          — initial grid placement
 *   data-drag-handle                 — drag-trigger element (titlebar)
 *   data-misp-widget-content         — render target for AJAX HTML
 *   data-misp-widget-title           — titlebar label span; client
 *                                      rewrites it on alias change (DD-18)
 *   data-misp-widget-action="..."    — clickable controls (refresh,
 *                                      configure, remove, export-json,
 *                                      export-csv)
 *   data-misp-menubutton(+ -trigger / -menu) — WAI-ARIA menu-button for
 *                                      the export (download) control;
 *                                      hydrated by menu-button.module.mjs
 *   data-misp-widget-refresh-indicator — Phase 5 "updated Ns ago" chip
 *                                        slot; RefreshIndicator writes text
 *   data-resize-handle               — pointer-down target for resize
 *
 * Themes may override THIS file (`Themed/<Name>/Elements/dashboard/
 * widget/wrapper.ctp`) freely so long as those hooks are preserved —
 * class names, element types, ordering, and inner structure are all
 * negotiable.
 *
 * Inputs:
 *   $widget — array shape {
 *     instance_id, widget, title, config (may carry an `alias`),
 *     schema, placeholder, position: {x, y, w, h}
 *   }
 *   The displayed label is config.alias (if non-empty) else `title`
 *   (the class $title) else the widget class name (DD-18).
 */
?>
<article class="misp-widget"
         data-misp-widget
         data-widget-name="<?= h($widget['widget']) ?>"
         data-widget-instance-id="<?= h($widget['instance_id']) ?>"
         data-widget-config='<?= h(json_encode($widget['config'], JSON_UNESCAPED_SLASHES)) ?>'
         data-widget-schema='<?= h(json_encode(isset($widget['schema']) && is_array($widget['schema']) ? $widget['schema'] : array(), JSON_UNESCAPED_SLASHES)) ?>'
         data-widget-placeholder="<?= h(isset($widget['placeholder']) && is_string($widget['placeholder']) ? $widget['placeholder'] : '') ?>"
         data-widget-title="<?= h(!empty($widget['title']) ? $widget['title'] : $widget['widget']) ?>"
         <?php if (!empty($widget['autoRefreshDelay']) && (int)$widget['autoRefreshDelay'] > 0): ?>data-widget-refresh-delay="<?= (int)$widget['autoRefreshDelay'] ?>"<?php endif; ?>
         data-position-x="<?= h($widget['position']['x']) ?>"
         data-position-y="<?= h($widget['position']['y']) ?>"
         data-position-w="<?= h($widget['position']['w']) ?>"
         data-position-h="<?= h($widget['position']['h']) ?>">
    <header class="misp-widget-titlebar" data-drag-handle>
<?php
    // Label precedence (DD-18): per-instance alias (config.alias) →
    // class $title → class name. The client mirrors this in
    // board.module's _applyTitle() when the alias changes live.
    $__alias = isset($widget['config']['alias']) && is_string($widget['config']['alias'])
        ? trim($widget['config']['alias']) : '';
    $__label = $__alias !== ''
        ? $__alias
        : (!empty($widget['title']) ? $widget['title'] : $widget['widget']);
?>
        <span class="misp-widget-title" data-misp-widget-title><?= h($__label) ?></span>
        <span class="misp-widget-refresh-indicator"
              data-misp-widget-refresh-indicator
              aria-live="polite"
              aria-atomic="true"></span>
        <span class="misp-widget-actions">
            <button type="button" class="misp-widget-iconbtn" data-misp-widget-action="refresh"   title="<?= __('Refresh') ?>"   aria-label="<?= __('Refresh') ?>"><i class="fas fa-sync" aria-hidden="true"></i></button>
            <button type="button" class="misp-widget-iconbtn" data-misp-widget-action="configure" title="<?= __('Configure') ?>" aria-label="<?= __('Configure') ?>"><i class="fas fa-cog" aria-hidden="true"></i></button>
            <span class="misp-widget-export" data-misp-menubutton>
                <button type="button" class="misp-widget-iconbtn" data-misp-menubutton-trigger aria-haspopup="menu" aria-expanded="false" title="<?= __('Export raw data') ?>" aria-label="<?= __('Export raw data') ?>"><i class="fas fa-download" aria-hidden="true"></i></button>
                <span class="misp-widget-menu" role="menu" data-misp-menubutton-menu hidden>
                    <button type="button" class="misp-widget-menuitem" role="menuitem" data-misp-widget-action="export-json"><?= __('Export as JSON') ?></button>
                    <button type="button" class="misp-widget-menuitem" role="menuitem" data-misp-widget-action="export-csv"><?= __('Export as CSV') ?></button>
                </span>
            </span>
            <button type="button" class="misp-widget-iconbtn misp-widget-iconbtn-edit-only" data-misp-widget-action="remove" title="<?= __('Remove') ?>" aria-label="<?= __('Remove') ?>"><i class="fas fa-times" aria-hidden="true"></i></button>
        </span>
    </header>
    <div class="misp-widget-body" data-misp-widget-content>
        <div class="misp-widget-loading"><?= __('Loading…') ?></div>
    </div>
    <span class="misp-widget-resize" data-resize-handle aria-hidden="true"></span>
</article>
