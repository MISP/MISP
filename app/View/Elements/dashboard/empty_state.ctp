<?php
/**
 * Empty-state for the dashboard board surface. Shown by
 * Dashboards/index.ctp when the resolved $widgets array is empty —
 * i.e. the user has no UserSetting:dashboard row (and no visible
 * default template from the dashboards table), OR the user has
 * explicitly saved an empty layout.
 *
 * Phase 2's in-page "Add widget" flow will land a CTA button here.
 * For Phase 1 the copy hints at the existing "⋯ More" menu's
 * Import / Browse Templates actions, which are the only widget-
 * sourcing routes available today.
 */
?>
<div class="misp-dashboard-emptystate" data-misp-dashboard-emptystate>
    <div class="misp-dashboard-emptystate-glyph" aria-hidden="true">
        <svg width="56" height="56" viewBox="0 0 56 56" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="6" y="6" width="18" height="18" rx="2" />
            <rect x="32" y="6" width="18" height="18" rx="2" stroke-dasharray="3 3" />
            <rect x="6" y="32" width="18" height="18" rx="2" stroke-dasharray="3 3" />
            <rect x="32" y="32" width="18" height="18" rx="2" stroke-dasharray="3 3" />
        </svg>
    </div>
    <h2 class="misp-dashboard-emptystate-title"><?= __('No widgets yet') ?></h2>
    <p class="misp-dashboard-emptystate-body">
        <?= __('Use the ⋯ menu to import a configuration or browse templates.') ?>
    </p>
</div>
