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
 *   data-widget-alias                — optional display alias
 *   data-position-{x,y,w,h}          — initial grid placement
 *   data-drag-handle                 — drag-trigger element (titlebar)
 *   data-misp-widget-content         — render target for AJAX HTML
 *   data-misp-widget-action="..."    — clickable controls
 *   data-resize-handle               — pointer-down target for resize
 *
 * Themes may override THIS file (`Themed/<Name>/Elements/dashboard/
 * widget/wrapper.ctp`) freely so long as those hooks are preserved —
 * class names, element types, ordering, and inner structure are all
 * negotiable.
 *
 * Inputs:
 *   $widget — array shape {
 *     instance_id, widget, alias, config, position: {x, y, w, h}
 *   }
 */
?>
<article class="misp-widget"
         data-misp-widget
         data-widget-name="<?= h($widget['widget']) ?>"
         data-widget-instance-id="<?= h($widget['instance_id']) ?>"
         data-widget-config='<?= h(json_encode($widget['config'], JSON_UNESCAPED_SLASHES)) ?>'
         data-widget-schema='<?= h(json_encode(isset($widget['schema']) && is_array($widget['schema']) ? $widget['schema'] : array(), JSON_UNESCAPED_SLASHES)) ?>'
         <?php if (!empty($widget['alias'])): ?>data-widget-alias="<?= h($widget['alias']) ?>"<?php endif; ?>
         data-position-x="<?= h($widget['position']['x']) ?>"
         data-position-y="<?= h($widget['position']['y']) ?>"
         data-position-w="<?= h($widget['position']['w']) ?>"
         data-position-h="<?= h($widget['position']['h']) ?>">
    <header class="misp-widget-titlebar" data-drag-handle>
        <span class="misp-widget-title"><?= h($widget['alias'] ?? $widget['widget']) ?></span>
        <span class="misp-widget-actions">
            <button type="button" class="misp-widget-iconbtn" data-misp-widget-action="refresh"   title="<?= __('Refresh') ?>"   aria-label="<?= __('Refresh') ?>">↻</button>
            <button type="button" class="misp-widget-iconbtn" data-misp-widget-action="configure" title="<?= __('Configure') ?>" aria-label="<?= __('Configure') ?>">⚙</button>
            <button type="button" class="misp-widget-iconbtn misp-widget-iconbtn-edit-only" data-misp-widget-action="remove" title="<?= __('Remove') ?>" aria-label="<?= __('Remove') ?>">✕</button>
        </span>
    </header>
    <div class="misp-widget-body" data-misp-widget-content>
        <div class="misp-widget-loading"><?= __('Loading…') ?></div>
    </div>
    <span class="misp-widget-resize" data-resize-handle aria-hidden="true"></span>
</article>
