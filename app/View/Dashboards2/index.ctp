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
// Phase 0.3 theme-overlay demo per PRD §8.1: the midnight stylesheet
// is always loaded; its rules only apply when [data-theme] is set on
// <html>. Production activation goes through MISP's regular theme
// system (Cake's Themed/<Name>); the ?theme query param is a
// prototype-only convenience for verification.
$themeOverlay = isset($this->request->params['named']['theme'])
    ? $this->request->params['named']['theme']
    : (isset($this->request->query['theme']) ? $this->request->query['theme'] : null);
$themeOverlay = preg_match('/^[a-z][a-z0-9_-]{0,30}$/', (string)$themeOverlay)
    ? $themeOverlay
    : null;
// uiTheme (set by the controller from ?ui_theme=...) activates the
// matching Themed/<Name> overlay. The Cake resolver auto-serves
// Themed/<Name>/webroot/* at /theme/<Name>/*, so we just emit a
// link tag at a predictable path: /theme/<Name>/css/dashboard/<name>.css.
$uiThemeCss = !empty($uiTheme)
    ? sprintf('%s/theme/%s/css/dashboard/%s.css', $baseurl, $uiTheme, strtolower($uiTheme))
    : null;
?>
<!DOCTYPE html>
<html lang="en"<?php
  if ($themeOverlay) echo ' data-theme="' . h($themeOverlay) . '"';
  if (!empty($uiTheme)) echo ' data-ui-theme="' . h($uiTheme) . '"';
?>>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>dashboard-v2 prototype — MISP</title>
<link rel="stylesheet" href="<?= h($baseurl) ?>/css/dashboard/dashboard.default.css">
<link rel="stylesheet" href="<?= h($baseurl) ?>/css/dashboard/dashboard.midnight.css">
<?php if ($uiThemeCss): ?>
<link rel="stylesheet" href="<?= h($uiThemeCss) ?>">
<?php endif; ?>
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

    <?php
    // Each widget renders through the wrapper element so themes can
    // surgically override it (PRD §8.3 Level 3). Cake's Themed resolver
    // picks app/View/Themed/<active>/Elements/dashboard-v2/widget/
    // wrapper.ctp when $this->theme is set; otherwise the default
    // element under app/View/Elements/ wins.
    foreach ($widgets as $w) {
        echo $this->element('dashboard-v2/widget/wrapper', array('widget' => $w));
    }
    ?>

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
