<?php
/**
 * StatGrid renderer (dashboard v2).
 *
 * A "more visually pleasing" alternative to SimpleList for KPI-style
 * key/value widgets (the admin Usage data widget first; reusable by any
 * widget whose handler() returns the same row shape). Renders each datum
 * as a metric card — small uppercase label, large prominent value, and an
 * optional coloured delta badge — in a responsive grid that wraps to the
 * widget's current width (one column when narrow, more as it widens).
 *
 * Data contract — identical to SimpleList, so a widget can switch render
 * kinds with no handler() change:
 *
 *   $data = [
 *     ['title' => '...', 'value' => mixed, 'drilldown' => '/url' (optional),
 *      'change' => int (optional, growth delta → ▲/▼ badge),
 *      'type' => 'gap' (optional → full-width section break; its `title`,
 *                if present, becomes the section heading),
 *      'html_title' => 'raw html' (optional, replaces the label),
 *      'html'  => 'raw html appended under the value' (legacy SimpleList
 *                 pattern, retained for drop-in parity)],
 *     ...
 *   ];
 *
 * URL safety for `drilldown` is gated by DashboardURLValidator (DD-03) —
 * unsafe URLs are dropped and the card renders as plain (non-link) markup.
 *
 * Label vs glyph (DD-32): when a row carries an `icon` name that resolves
 * via StatGlyph, the card shows that inline-SVG glyph instead of the text
 * label (which truncates in narrow cards) and the full field name moves to
 * the card's `title` hover tooltip. A row without a (resolvable) icon keeps
 * the text label, so StatGrid stays a drop-in for icon-less widgets.
 *
 * No inline styles / hardcoded colours: visuals come from the token-driven
 * .misp-stat-* rules in dashboard.default.css, so themes (midnight) that
 * only redefine the --misp-dash-* tokens retone this for free.
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');
App::uses('StatGlyph', 'Lib/Dashboard/Tools');

if (empty($data)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

/**
 * Format a scalar value for display: group integers with thousands
 * separators, keep one decimal for non-integer numerics, and leave
 * pre-formatted strings ("96 (68 %)", "N/A") untouched.
 */
$formatValue = function ($raw) {
    if (is_array($raw)) {
        return implode(', ', array_map(function ($v) {
            return is_array($v) ? '[Array]' : h($v);
        }, $raw));
    }
    if (is_int($raw) || is_float($raw) || (is_string($raw) && is_numeric($raw))) {
        $num = $raw + 0;
        return ($num == (int)$num)
            ? number_format((int)$num)
            : number_format($num, 1);
    }
    return h($raw);
};

echo '<div class="misp-stat-grid">';
foreach ($data as $row) {
    // A gap row becomes a full-width section break; its title (if any)
    // labels the break.
    if (!empty($row['type']) && $row['type'] === 'gap') {
        if (!empty($row['title'])) {
            echo '<div class="misp-stat-section">' . h($row['title']) . '</div>';
        } else {
            echo '<div class="misp-stat-section misp-stat-section-blank"></div>';
        }
        continue;
    }

    // Plain-text field name for the hover tooltip / accessible name.
    $titleText = isset($row['html_title'])
        ? trim(strip_tags($row['html_title']))
        : (string)($row['title'] ?? '');

    // Glyph replaces the text label when a resolvable icon is given;
    // otherwise fall back to the (possibly creator-HTML) text label.
    $glyph = StatGlyph::get($row['icon'] ?? null);
    $header = $glyph !== ''
        ? '<span class="misp-stat-glyph">' . $glyph . '</span>'
        : '<span class="misp-stat-label">'
            . (isset($row['html_title']) ? $row['html_title'] : h($titleText))
            . '</span>';

    $value = isset($row['value']) ? $formatValue($row['value']) : '';

    // Delta badge: positive growth = success (▲), negative = danger (▼).
    $delta = '';
    if (!empty($row['change'])) {
        $d = (int)$row['change'];
        $cls = $d > 0 ? 'misp-stat-delta-up' : 'misp-stat-delta-down';
        $arrow = $d > 0 ? '&#9650;' : '&#9660;';   // ▲ / ▼
        $delta = sprintf(
            '<span class="misp-stat-delta %s"><span class="misp-stat-arrow">%s</span>%s</span>',
            $cls,
            $arrow,
            number_format(abs($d))
        );
    }

    // Legacy `html` field (e.g. MispStatusWidget's "(View)" link), shown
    // as a muted footer line — retained for SimpleList drop-in parity.
    $legacyHtml = !empty($row['html'])
        ? '<div class="misp-stat-html">' . $row['html'] . '</div>'
        : '';

    $inner = sprintf(
        '%s<span class="misp-stat-valuerow"><span class="misp-stat-value">%s</span>%s</span>%s',
        $header,
        $value,
        $delta,
        $legacyHtml
    );

    // Full field name on the card so it surfaces as a hover tooltip
    // (and an accessible name) now that the visible label is a glyph.
    $titleAttr = $titleText !== '' ? ' title="' . h($titleText) . '"' : '';

    // Whole card is a link when a safe drilldown URL is present (DD-03).
    $href = null;
    if (!empty($row['drilldown'])) {
        $href = DashboardURLValidator::validate($row['drilldown']);
    }
    if ($href !== null) {
        echo sprintf('<a class="misp-stat-card" href="%s"%s>%s</a>', h($href), $titleAttr, $inner);
    } else {
        echo sprintf('<div class="misp-stat-card"%s>%s</div>', $titleAttr, $inner);
    }
}
echo '</div>';
