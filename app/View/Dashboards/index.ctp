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
