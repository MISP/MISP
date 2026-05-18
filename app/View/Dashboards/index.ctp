<?php
/**
 * Dashboard index view. Renders inside Layouts/dashboard.ctp (DD-08),
 * which provides the MISP chrome (global menu, flash, footer) and
 * loads the dashboard's CSS. This view emits only the dashboard's
 * own markup + the JS module bootstrap.
 *
 * Hook contract per PRD §8.5:
 *   - data-misp-board-root        — board root element
 *   - data-misp-widget            — one widget instance
 *   - data-widget-name            — widget class name
 *   - data-widget-instance-id     — stable instance id
 *   - data-widget-config          — JSON-encoded config
 *   - data-misp-widget-content    — render target
 *   - data-misp-widget-action="*" — clickable widget controls
 *   - data-misp-board-action="*"  — board-level toolbar controls
 */
$baseurl = Configure::read('MISP.baseurl') ?: '';
?>
<header class="misp-dashboard-header">
    <h1 class="misp-dashboard-title"><?= __('Dashboard') ?></h1>
    <!-- Bulk-edit toolbar slot (DD-05). Toolbar module populates this
         with one chip per canonical type that at least one widget on
         the board declares; an empty-state hint shows otherwise. -->
    <div class="misp-dashboard-toolbar"
         data-misp-board-toolbar
         aria-label="<?= __('Dashboard filters') ?>"></div>
    <div class="misp-dashboard-modecontrols">
        <button type="button"
                class="misp-dashboard-btn"
                data-misp-board-action="toggle-mode"
                aria-pressed="false">
            <?= __('Edit layout') ?>
        </button>

        <!-- "⋯ More" dropdown (DD-08). Hosts the four template
             actions; each points at the v1 carryover URL. Phase 4
             reimplements these as in-page flows. WAI-ARIA Menu
             Button pattern — see menu-button.module.mjs. -->
        <div class="misp-dashboard-menubutton" data-misp-menubutton>
            <button type="button"
                    class="misp-dashboard-btn misp-dashboard-btn-icon"
                    aria-haspopup="menu"
                    aria-expanded="false"
                    aria-controls="misp-dashboard-more-menu"
                    aria-label="<?= __('More actions') ?>"
                    title="<?= __('More actions') ?>"
                    data-misp-menubutton-trigger>
                <span class="misp-dashboard-menubutton-glyph" aria-hidden="true">&#x22EF;</span>
            </button>
            <div class="misp-dashboard-menu"
                 id="misp-dashboard-more-menu"
                 role="menu"
                 aria-label="<?= __('More actions') ?>"
                 hidden
                 data-misp-menubutton-menu>
                <a role="menuitem"
                   tabindex="-1"
                   class="misp-dashboard-menuitem"
                   href="<?= h($baseurl) ?>/dashboards/import">
                    <span class="misp-dashboard-menuitem-icon" aria-hidden="true">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M8 2.5v7" />
                            <path d="M5 6.5l3 3 3-3" />
                            <path d="M2.5 11.5v1a1 1 0 001 1h9a1 1 0 001-1v-1" />
                        </svg>
                    </span>
                    <span class="misp-dashboard-menuitem-label"><?= __('Import configuration…') ?></span>
                </a>
                <a role="menuitem"
                   tabindex="-1"
                   class="misp-dashboard-menuitem"
                   href="<?= h($baseurl) ?>/dashboards/export">
                    <span class="misp-dashboard-menuitem-icon" aria-hidden="true">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M8 9.5v-7" />
                            <path d="M5 5.5l3-3 3 3" />
                            <path d="M2.5 11.5v1a1 1 0 001 1h9a1 1 0 001-1v-1" />
                        </svg>
                    </span>
                    <span class="misp-dashboard-menuitem-label"><?= __('Export configuration…') ?></span>
                </a>
                <hr class="misp-dashboard-menu-separator" aria-hidden="true">
                <a role="menuitem"
                   tabindex="-1"
                   class="misp-dashboard-menuitem"
                   href="<?= h($baseurl) ?>/dashboards/saveTemplate">
                    <span class="misp-dashboard-menuitem-icon" aria-hidden="true">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M4 2.5h8v11l-4-2.75L4 13.5v-11z" />
                        </svg>
                    </span>
                    <span class="misp-dashboard-menuitem-label"><?= __('Save as template…') ?></span>
                </a>
                <a role="menuitem"
                   tabindex="-1"
                   class="misp-dashboard-menuitem"
                   href="<?= h($baseurl) ?>/dashboards/listTemplates">
                    <span class="misp-dashboard-menuitem-icon" aria-hidden="true">
                        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="2" y="2" width="5" height="5" rx="1" />
                            <rect x="9" y="2" width="5" height="5" rx="1" />
                            <rect x="2" y="9" width="5" height="5" rx="1" />
                            <rect x="9" y="9" width="5" height="5" rx="1" />
                        </svg>
                    </span>
                    <span class="misp-dashboard-menuitem-label"><?= __('Browse templates') ?></span>
                </a>
            </div>
        </div>
    </div>
</header>

<main class="misp-dashboard-main"
      data-misp-board-root
      data-misp-board-mode="view"
      data-misp-board-renderwidget-url="<?= h($baseurl) ?>/dashboards/renderWidget"
      data-misp-board-save-url="<?= h($baseurl) ?>/dashboards/updateSettings">

    <?php
    // Each widget renders through the wrapper element so themes can
    // surgically override it (PRD §8.3 Level 3). Cake's Themed resolver
    // picks app/View/Themed/<active>/Elements/dashboard/widget/
    // wrapper.ctp when $this->theme is set; otherwise the default
    // element under app/View/Elements/ wins.
    foreach ($widgets as $w) {
        echo $this->element('dashboard/widget/wrapper', array('widget' => $w));
    }
    ?>

</main>

<footer class="misp-dashboard-footer">
    <code data-misp-debug-readout>{}</code>
</footer>

<!-- Configure side panel (schema-driven two-tier form per DD-06).
     Hidden by default; shown by the ConfigureModule when the user clicks a
     widget's ⚙ button. Single panel per board; opening for a different widget
     repopulates the form. Matches the PRD §8.5 contract via stable
     data-misp-configure-* hooks so a theme can override the markup. -->
<div class="misp-configure-backdrop" data-misp-configure-backdrop hidden></div>
<aside class="misp-configure-panel"
       data-misp-configure-root
       role="dialog"
       aria-labelledby="misp-configure-title"
       aria-modal="true"
       hidden>
    <header class="misp-configure-header">
        <h2 id="misp-configure-title" class="misp-configure-title"
            data-misp-configure-title><?= __('Configure') ?></h2>
        <button type="button"
                class="misp-widget-iconbtn"
                data-misp-configure-action="cancel"
                title="<?= __('Close') ?>"
                aria-label="<?= __('Close') ?>">✕</button>
    </header>
    <div class="misp-configure-body" data-misp-configure-body></div>
    <footer class="misp-configure-footer">
        <button type="button"
                class="misp-dashboard-btn"
                data-misp-configure-action="cancel"><?= __('Cancel') ?></button>
        <button type="button"
                class="misp-dashboard-btn misp-dashboard-btn-primary"
                data-misp-configure-action="save"><?= __('Save') ?></button>
    </footer>
</aside>

<script type="module" src="<?= h($baseurl) ?>/js/dashboard/board.module.mjs"></script>
