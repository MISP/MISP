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
 *      'tooltip' => '...' (optional → the card's hover `title` attribute;
 *                overrides the default field-name tooltip — e.g. to explain
 *                why a value reads "N/A"),
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
 * Opt-in labels (AD-21): a widget can set a public `$statGridLabels = true`
 * to render the glyph AND the text label together (glyph left, uppercase
 * label beside it) instead of the glyph-only default. The dense admin
 * UsageDataWidget leaves it unset and is unchanged; the analyst New-data
 * widget opts in so each KPI card is self-labelled, not glyph-only.
 *
 * misp-iconify glyphs (AD-21): a row's `icon_class` (a misp-icon name, e.g.
 * 'event') renders the masked-SVG misp-iconify glyph from misp-iconify.css
 * (currentColor → themes for free) instead of a StatGlyph inline SVG;
 * StatGlyph `icon` stays the path for the admin UsageDataWidget.
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

// Opt-in labels (AD-21): hoisted once so it also picks the grid variant
// (labeled cards get wider columns + 2-line labels; glyph-only stays dense).
$statLabels = isset($widget) && !empty($widget->statGridLabels);
echo '<div class="misp-stat-grid' . ($statLabels ? ' misp-stat-grid-labeled' : '') . '">';
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

    // Glyph replaces the text label when a resolvable icon is given
    // (DD-32) — unless the widget opted into labels ($statGridLabels,
    // AD-21), in which case the glyph and label render together. A row
    // without a (resolvable) icon always keeps the text label.
    // A row may carry a misp-iconify icon (`icon_class` = a misp-icon NAME,
    // rendered as a masked-SVG <span> from misp-iconify.css — currentColor, so
    // it themes for free) or a StatGlyph inline-SVG (`icon` = a StatGlyph NAME,
    // the admin UsageDataWidget's path). icon_class wins when both are set.
    $glyphMarkup = '';
    if (!empty($row['icon_class'])) {
        $cls = preg_replace('/[^a-z0-9_-]/', '', strtolower((string)$row['icon_class']));
        if ($cls !== '') {
            $glyphMarkup = '<span class="misp-stat-glyph"><span class="misp-icon misp-icon-'
                . $cls . ' misp-simple" aria-hidden="true"></span></span>';
        }
    } elseif (($glyph = StatGlyph::get($row['icon'] ?? null)) !== '') {
        $glyphMarkup = '<span class="misp-stat-glyph">' . $glyph . '</span>';
    }
    $labelMarkup = '<span class="misp-stat-label">'
        . (isset($row['html_title']) ? $row['html_title'] : h($titleText))
        . '</span>';
    if ($glyphMarkup !== '') {
        $header = $statLabels
            ? '<span class="misp-stat-head">' . $glyphMarkup . $labelMarkup . '</span>'
            : $glyphMarkup;
    } else {
        $header = $labelMarkup;
    }

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

    // Card tooltip: an explicit `tooltip` row key wins (a widget can explain a
    // value — e.g. why a metric reads "N/A"); otherwise fall back to the full
    // field name, which surfaces the label as a hover tooltip (and an
    // accessible name) now that the visible header may be a glyph.
    $tooltipText = !empty($row['tooltip']) ? trim((string)$row['tooltip']) : $titleText;
    $titleAttr = $tooltipText !== '' ? ' title="' . h($tooltipText) . '"' : '';

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
