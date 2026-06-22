<?php
/**
 * Dashboard light/dark boot (DD-51).
 *
 * Inline + synchronous so it runs in <head> before first paint: it sets
 * data-theme on <html> before the body is rendered, so the dashboard
 * never flashes light before going dark (no FOUC). Included by all three
 * dashboard layouts (default + Themed/Overmind + Themed/UiBeta), which
 * each already load dashboard.midnight.css.
 *
 * Seeded with the per-user preference resolved server-side in
 * DashboardsController::index ($dashboardThemePref):
 *   - 'dark'  -> force the midnight overlay
 *   - 'light' -> force light (leave data-theme unset)
 *   - 'auto'  -> follow the browser's prefers-color-scheme
 *
 * The live toggle (board.module.mjs) flips the same attribute and
 * persists an explicit light/dark via /dashboards/updateTheme.
 * dashboard.midnight.css keys off :root[data-theme="midnight"].
 */
$pref = isset($dashboardThemePref) ? $dashboardThemePref : 'auto';
?>
<script>
(function () {
    var pref = <?= json_encode($pref) ?>;
    var dark = pref === 'dark' || (pref !== 'light' &&
        window.matchMedia &&
        window.matchMedia('(prefers-color-scheme: dark)').matches);
    if (dark) {
        document.documentElement.setAttribute('data-theme', 'midnight');
    }
})();
</script>
