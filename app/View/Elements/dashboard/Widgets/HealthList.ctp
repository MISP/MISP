<?php
/**
 * HealthList renderer (dashboard v2 — DD-39).
 *
 * An issue-only health rollup renderer for the MISP health widget
 * (MispAdminHealthWidget first; reusable by any future health-check
 * surface). Each row is shaped:
 *
 *     [severity glyph] check_name [detail text]    [severity chip]
 *
 * The renderer is dumb / token-driven: the widget owns all severity
 * decisions and emits an allow-listed `severity_class` per row; this
 * renderer only maps the named class to the matching
 * .misp-health-chip-<sem> token pair and to the matching glyph SVG.
 * Adding a new severity stop = adding one CSS rule + one glyph branch.
 *
 * Data contract — a flat list of typed rows:
 *
 *   $data = [
 *     // Always-rendered summary header (one):
 *     ['type' => 'header',
 *      'value' => 'All checks passing' | '3 issues found',
 *      'severity' => 'success'|'warning'|'danger'],
 *
 *     // A check row (only non-OK checks reach the renderer; the widget
 *     // filters info-tier results out before emitting):
 *     ['type'  => 'check',
 *      'check' => 'php-memory-limit',         // stable id (audit/test)
 *      'name'  => 'PHP memory_limit low',     // visible label
 *      'detail'=> '1024M (recommended 2048M)',// optional one-line detail
 *      'severity_class' => 'warning',         // warning|danger
 *      'drilldown' => '/servers/serverSettings/diagnostics'],
 *
 *     // A full-width message (diagnostics-unreachable / cache-stale etc.):
 *     ['type' => 'message', 'title' => '...', 'value' => '...'],
 *   ];
 *
 * Severity glyph set is intentionally narrow (two — warning + danger):
 * the chip + glyph already carry the colour signal together, so a
 * per-check icon would compete for the same attention. Inline SVG +
 * `currentColor` keeps the glyphs theme-independent (DD-32 lesson).
 *
 * Escaping (DD-34): widget handler()s emit RAW strings — this renderer
 * h()s every interpolated scalar exactly once. Drilldown URL safety is
 * gated by DashboardURLValidator (DD-03): unsafe / off-host URLs are
 * dropped and the row renders un-linked.
 *
 * No inline styles / hardcoded colours: visuals come from the
 * token-driven .misp-health-* rules in dashboard.default.css, so
 * themes that only redefine the --misp-dash-* tokens retone this for
 * free. This renderer is NOT its own scroll/size container —
 * .misp-widget-body owns padding + overflow (DD-31 rule).
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

if (empty($data)) {
    echo '<div class="misp-health-message"><span class="misp-health-message-text">'
        . __('No data.') . '</span></div>';
    return;
}

$validSeverity = array('warning', 'danger');
$validHeaderSeverity = array('success', 'warning', 'danger');

// Inline SVG glyphs, severity-bound. currentColor + 24x24 viewBox; the
// .misp-health-glyph-svg CSS rule sizes them.
$glyphSvg = array(
    'warning' =>
        '<svg class="misp-health-glyph-svg" viewBox="0 0 24 24" '
        . 'aria-hidden="true" focusable="false">'
        . '<path fill="currentColor" '
        . 'd="M12 2.5 22.5 21H1.5L12 2.5Zm0 5.2L4.6 19.5h14.8L12 7.7Z"/>'
        . '<path fill="currentColor" '
        . 'd="M11 10h2v5h-2zM11 16.2h2v2h-2z"/>'
        . '</svg>',
    'danger' =>
        '<svg class="misp-health-glyph-svg" viewBox="0 0 24 24" '
        . 'aria-hidden="true" focusable="false">'
        . '<circle cx="12" cy="12" r="9.5" fill="none" '
        . 'stroke="currentColor" stroke-width="1.8"/>'
        . '<path fill="currentColor" '
        . 'd="M11 6.5h2v8h-2zM11 16.2h2v2h-2z"/>'
        . '</svg>',
    'success' =>
        '<svg class="misp-health-glyph-svg" viewBox="0 0 24 24" '
        . 'aria-hidden="true" focusable="false">'
        . '<circle cx="12" cy="12" r="9.5" fill="none" '
        . 'stroke="currentColor" stroke-width="1.8"/>'
        . '<path fill="none" stroke="currentColor" stroke-width="2" '
        . 'stroke-linecap="round" stroke-linejoin="round" '
        . 'd="M7.5 12.5l3 3 6-6.5"/>'
        . '</svg>',
);

echo '<div class="misp-health-list">';
foreach ($data as $row) {
    $type = isset($row['type']) ? $row['type']
        : (isset($row['check']) ? 'check' : 'message');

    if ($type === 'header') {
        $sev = isset($row['severity']) && in_array($row['severity'], $validHeaderSeverity, true)
            ? $row['severity']
            : 'success';
        $glyph = isset($glyphSvg[$sev]) ? $glyphSvg[$sev] : '';
        echo '<div class="misp-health-header misp-health-header-' . h($sev) . '">'
            . '<span class="misp-health-glyph">' . $glyph . '</span>'
            . '<span class="misp-health-headtext">' . h($row['value'] ?? '') . '</span>'
            . '</div>';
        continue;
    }

    if ($type === 'message') {
        $title = !empty($row['title'])
            ? '<span class="misp-health-message-title">' . h($row['title']) . '</span>'
            : '';
        $text = isset($row['value'])
            ? '<span class="misp-health-message-text">' . h($row['value']) . '</span>'
            : '';
        echo '<div class="misp-health-message">' . $title . $text . '</div>';
        continue;
    }

    // ---- check row ----
    $name = isset($row['name']) ? (string)$row['name']
        : (isset($row['check']) ? (string)$row['check'] : '');
    $detail = isset($row['detail']) ? (string)$row['detail'] : '';
    $sev = isset($row['severity_class']) && in_array($row['severity_class'], $validSeverity, true)
        ? $row['severity_class']
        : 'warning';
    $glyph = isset($glyphSvg[$sev]) ? $glyphSvg[$sev] : '';

    $label = '<span class="misp-health-label">'
        . '<span class="misp-health-glyph">' . $glyph . '</span>'
        . '<span class="misp-health-body">'
        . '<span class="misp-health-name">' . h($name) . '</span>'
        . ($detail !== ''
            ? '<span class="misp-health-detail">' . h($detail) . '</span>'
            : '')
        . '</span>'
        . '</span>';

    $chip = sprintf(
        '<span class="misp-health-chip misp-health-chip-%s">%s</span>',
        h($sev),
        h(__($sev === 'danger' ? 'fail' : 'warn'))
    );

    $inner = $label . '<span class="misp-health-chips">' . $chip . '</span>';

    $href = null;
    if (!empty($row['drilldown'])) {
        $href = DashboardURLValidator::validate($row['drilldown']);
    }
    if ($href !== null) {
        echo sprintf(
            '<a class="misp-health-row misp-health-row-%s" href="%s">%s</a>',
            h($sev),
            h($href),
            $inner
        );
    } else {
        echo sprintf(
            '<div class="misp-health-row misp-health-row-%s">%s</div>',
            h($sev),
            $inner
        );
    }
}
echo '</div>';
