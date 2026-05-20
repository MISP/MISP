<?php
/**
 * Attack renderer (dashboard v2).
 *
 * Static ATT&CK heatmap for widgets that declare `$render = 'Attack'`
 * (AttackWidget). The handler returns the full Event::restSearch
 * 'attack' export shape:
 *
 *   $data = [
 *     'tabs'          => [ <tabName> => [ <colName> => [ {item}, ... ], ... ], ... ],
 *     'columnOrders'  => [ <tabName> => [ colName, colName, ... ], ... ],
 *     'scores'        => [ <tag_name> => int, ... ],
 *     'colours'       => [ <tag_name> => '#rrggbb', ... ],   // precomputed
 *     'maxScore'      => int,
 *     'defaultTabName'=> '<tabName>',
 *     'removeTrailing'=> int,    // strip N space-separated chunks from the end
 *     'galaxyName'    => string,
 *     ... (other keys ignored by this renderer)
 *   ];
 *
 * Each `{item}` carries: `id`, `value`, `tag_name` (the scores/colours
 * lookup key), `description`.
 *
 * Why not delegate to view_galaxy_matrix.ctp:
 *   v1 reused that 282-line element verbatim. It pulls in BS-classed
 *   markup, picking-mode form widgets, tab navigation, and a script
 *   tail — for an interactive matrix viewer it's the right tool, but
 *   AttackWidget is a 3×4 dashboard cell. The interactive surface
 *   doesn't fit; the script tail collides on multi-widget pages.
 *
 * v2 renders the DEFAULT TAB ONLY as a static heatmap — columns =
 * MITRE tactics, cells = techniques stacked vertically. Each cell is
 * a thin colored bar; hit cells get the precomputed `colours[tag_name]`
 * background, no-hit cells get a muted surface. Hover tooltip via the
 * `title` attribute carries the full technique name + score.
 *
 * Horizontal scroll inside `.misp-attack-scroll` handles the wide
 * matrix (14+ tactic columns won't fit a 3×4 widget body — that's
 * expected; the widget is a glanceable density map, not a navigable
 * surface).
 *
 * Token-driven CSS lives in dashboard.default.css under
 * "Attack renderer".
 */
if (!is_array($data) || empty($data)) {
    echo '<div class="misp-list-empty">' . __('No filter configured. Set the `filters` config to populate the heatmap.') . '</div>';
    return;
}

$tabs           = isset($data['tabs'])           ? (array)$data['tabs']           : array();
$columnOrders   = isset($data['columnOrders'])   ? (array)$data['columnOrders']   : array();
$scores         = isset($data['scores'])         ? (array)$data['scores']         : array();
$colours        = isset($data['colours'])        ? (array)$data['colours']        : array();
$defaultTab     = isset($data['defaultTabName']) ? (string)$data['defaultTabName'] : '';
$removeTrailing = isset($data['removeTrailing']) ? (int)$data['removeTrailing']    : 0;

if (empty($tabs) || $defaultTab === '' || empty($tabs[$defaultTab])) {
    echo '<div class="misp-list-empty">' . __('No matrix data returned.') . '</div>';
    return;
}

$tabCols = $tabs[$defaultTab];
$colOrder = isset($columnOrders[$defaultTab]) && is_array($columnOrders[$defaultTab])
    ? $columnOrders[$defaultTab]
    : array_keys($tabCols);

/**
 * Strip the last $removeTrailing space-separated chunks from a value.
 * v1's view_galaxy_matrix.ctp idiom — turns
 * "Phishing - T1566" + removeTrailing=2 into "Phishing".
 */
$stripTrailing = function ($value, $n) {
    if ($n <= 0 || !is_string($value) || $value === '') return $value;
    $parts = explode(' ', $value);
    if (count($parts) <= $n) return $value;
    return implode(' ', array_slice($parts, 0, count($parts) - $n));
};

/**
 * Format a tactic column name for display: replace `-` with space and
 * uppercase each word's first letter. "defense-evasion" → "Defense
 * Evasion".
 */
$formatTactic = function ($key) {
    return ucwords(str_replace('-', ' ', (string)$key));
};

echo '<div class="misp-attack">';
echo '<div class="misp-attack-scroll">';
echo '<div class="misp-attack-grid">';
foreach ($colOrder as $colKey) {
    if (!isset($tabCols[$colKey])) continue;
    $cells = (array)$tabCols[$colKey];

    // Per-tactic hit count = number of techniques with a non-zero score.
    $hitCount = 0;
    foreach ($cells as $cell) {
        $tag = isset($cell['tag_name']) ? $cell['tag_name'] : null;
        if ($tag !== null && !empty($scores[$tag])) $hitCount++;
    }

    echo '<div class="misp-attack-col">';
    echo '<div class="misp-attack-col-header">';
    echo '<span class="misp-attack-col-name" title="' . h($colKey) . '">' . h($formatTactic($colKey)) . '</span>';
    if ($hitCount > 0) {
        echo '<span class="misp-attack-col-count">' . (int)$hitCount . '</span>';
    }
    echo '</div>';

    echo '<div class="misp-attack-col-cells">';
    foreach ($cells as $cell) {
        if (!is_array($cell)) continue;
        $value = isset($cell['value']) ? (string)$cell['value'] : '';
        $tag   = isset($cell['tag_name']) ? (string)$cell['tag_name'] : '';
        $name  = $stripTrailing($value, $removeTrailing);
        $score = ($tag !== '' && isset($scores[$tag])) ? (int)$scores[$tag] : 0;
        $colour = ($score > 0 && isset($colours[$tag])) ? (string)$colours[$tag] : '';

        // Validate the colour against #rgb / #rrggbb to keep the
        // style attribute injection-safe.
        $safeColour = preg_match('/^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/', $colour) ? $colour : '';

        $cls = 'misp-attack-cell' . ($score > 0 ? ' misp-attack-cell--hit' : '');
        $style = $safeColour !== '' ? ' style="background-color:' . $safeColour . '"' : '';
        $tooltip = $score > 0
            ? $name . ' (' . $score . ')'
            : $name;
        printf(
            '<span class="%s"%s title="%s" aria-label="%s"></span>',
            h($cls),
            $style,
            h($tooltip),
            h($tooltip)
        );
    }
    echo '</div>';
    echo '</div>';
}
echo '</div>';
echo '</div>';
echo '</div>';
