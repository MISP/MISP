<?php
/**
 * Phase 0.3 prototype index view for dashboard v2.
 *
 * Standalone page (no MISP layout). Renders the dashboard frame with
 * the §8.5 stable hook contract:
 *   - data-misp-board-root        — board root element
 *   - data-misp-widget            — one widget instance
 *   - data-widget-name            — widget class name
 *   - data-widget-instance-id     — stable instance id
 *   - data-widget-config          — JSON-encoded config
 *   - data-misp-widget-content    — render target
 *   - data-misp-widget-action="*" — clickable widget controls
 *   - data-misp-board-action="*"  — board-level toolbar controls
 *
 * The view is intentionally minimal — Phase 0.3 commits 2 (CSS
 * tokens) and 3 (JS hook contract) populate the styling and
 * behaviour. This commit just sets up the markup.
 */
$baseurl = Configure::read('MISP.baseurl') ?: '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dashboard-v2 prototype — MISP</title>
<link rel="stylesheet" href="<?= h($baseurl) ?>/css/dashboard/dashboard.default.css">
</head>
<body class="misp-dashboard-page">

<header class="misp-dashboard-header">
    <h1 class="misp-dashboard-title">Dashboard <span class="misp-dashboard-pill">v2 proto</span></h1>
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
      data-misp-board-renderwidget-url="<?= h($baseurl) ?>/dashboards2/renderWidget"
      data-misp-board-save-url="<?= h($baseurl) ?>/dashboards2/updateSettings">

    <?php foreach ($widgets as $w): ?>
    <article class="misp-widget"
             data-misp-widget
             data-widget-name="<?= h($w['widget']) ?>"
             data-widget-instance-id="<?= h($w['instance_id']) ?>"
             data-widget-config='<?= h(json_encode($w['config'], JSON_UNESCAPED_SLASHES)) ?>'
             data-position-x="<?= h($w['position']['x']) ?>"
             data-position-y="<?= h($w['position']['y']) ?>"
             data-position-w="<?= h($w['position']['w']) ?>"
             data-position-h="<?= h($w['position']['h']) ?>">
        <header class="misp-widget-titlebar" data-drag-handle>
            <span class="misp-widget-title"><?= h($w['alias'] ?? $w['widget']) ?></span>
            <span class="misp-widget-actions">
                <button type="button" class="misp-widget-iconbtn" data-misp-widget-action="refresh" title="<?= __('Refresh') ?>" aria-label="<?= __('Refresh') ?>">↻</button>
                <button type="button" class="misp-widget-iconbtn" data-misp-widget-action="configure" title="<?= __('Configure') ?>" aria-label="<?= __('Configure') ?>">⚙</button>
                <button type="button" class="misp-widget-iconbtn misp-widget-iconbtn-edit-only" data-misp-widget-action="remove" title="<?= __('Remove') ?>" aria-label="<?= __('Remove') ?>">✕</button>
            </span>
        </header>
        <div class="misp-widget-body" data-misp-widget-content>
            <div class="misp-widget-loading"><?= __('Loading…') ?></div>
        </div>
        <span class="misp-widget-resize" data-resize-handle aria-hidden="true"></span>
    </article>
    <?php endforeach; ?>

</main>

<footer class="misp-dashboard-footer">
    <code data-misp-debug-readout>{}</code>
</footer>

<!-- Configure side panel (Phase 0.3 commit: schema-driven two-tier form per DD-06).
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

<script type="module" src="<?= h($baseurl) ?>/js/dashboard-v2/board.module.mjs"></script>

</body>
</html>
