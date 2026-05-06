<?php
/**
 * SimpleList renderer (dashboard v2).
 *
 * Renders a flat list of {title, value, ...} rows.  The widget data
 * shape is whatever the v1 SimpleList renderer accepts plus DD-03
 * per-datum drilldown:
 *
 *   $data = [
 *     ['title' => '...', 'value' => mixed, 'drilldown' => '/url' (optional),
 *      'change' => int (optional), 'type' => 'gap' (optional, blank row),
 *      'html_title' => 'raw html' (optional, replaces title),
 *      'html'  => 'raw html appended to value' (legacy MispStatusWidget pattern,
 *                 retained until Phase 2 $schema backfill migrates to drilldown)],
 *     ...
 *   ];
 *
 * No inline styles, no hardcoded colour classes — visuals come from
 * dashboard.default.css's token-driven .misp-list-* rules below.
 */
if (empty($data)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

foreach ($data as $row) {
    if (!empty($row['type']) && $row['type'] === 'gap') {
        echo '<div class="misp-list-gap"></div>';
        continue;
    }

    $title = isset($row['html_title'])
        ? $row['html_title']                  // creator-supplied HTML (rare)
        : h($row['title'] ?? '');

    // Wrap title in a link when DD-03 drilldown URL is present.
    // Validation belongs in DashboardURLValidator (Phase 1); for the
    // proto we limit href to relative or same-origin, falling back
    // to plain text otherwise.
    if (!empty($row['drilldown']) && _isSafeDashboardUrl($row['drilldown'])) {
        $title = sprintf(
            '<a class="misp-list-link" href="%s">%s</a>',
            h($row['drilldown']),
            $title
        );
    }

    // Value: scalar, array (joined), or absent.
    $value = '';
    if (isset($row['value'])) {
        if (is_array($row['value'])) {
            $items = array_map(function ($v) {
                return is_array($v) ? '[Array]' : h($v);
            }, $row['value']);
            $value = '<br>' . implode('<br>', $items);
        } else {
            $value = h($row['value']);
        }
    }

    // Optional change/delta indicator (positive=success, negative=danger).
    $change = '';
    if (!empty($row['change'])) {
        $delta = (int)$row['change'];
        $cls = $delta > 0 ? 'misp-list-delta-positive' : 'misp-list-delta-negative';
        $sign = $delta > 0 ? '+' : '';
        $change = sprintf(
            ' <span class="%s">(%s%d)</span>',
            $cls,
            $sign,
            $delta
        );
    }

    // Legacy `html` field (MispStatusWidget's `(View)` link). Will go
    // away once DD-03 per-datum drilldown is the only convention.
    $legacyHtml = $row['html'] ?? '';

    echo sprintf(
        '<div class="misp-list-row"><span class="misp-list-title">%s</span><span class="misp-list-sep">:</span> <span class="misp-list-value">%s</span>%s%s</div>',
        $title,
        $value,
        $legacyHtml,
        $change
    );
}

/**
 * Inline placeholder for the proper Phase 1 DashboardURLValidator helper.
 * Accepts: relative URLs starting with `/`, or absolute URLs that share
 * the host of MISP.baseurl. Rejects everything else (including
 * javascript:, data:, off-host).
 */
function _isSafeDashboardUrl($url) {
    if (!is_string($url) || $url === '') return false;
    if ($url[0] === '/' && (!isset($url[1]) || $url[1] !== '/')) return true;
    $base = (string)Configure::read('MISP.baseurl');
    if ($base === '') return false;
    $baseHost = parse_url($base, PHP_URL_HOST);
    $host = parse_url($url, PHP_URL_HOST);
    return $baseHost && $host && strcasecmp($baseHost, $host) === 0;
}
