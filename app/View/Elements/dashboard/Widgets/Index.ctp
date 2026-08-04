<?php
/**
 * Index renderer (dashboard v2).
 *
 * Renders a tabular index of records produced by widgets that declare
 * `$render = 'Index'` (EventStreamWidget, NewUsersWidget, NewOrgsWidget,
 * and any future widget that returns the same shape).
 *
 * Expected $data shape:
 *   [
 *     'data'        => [ <record>, ... ],   // Cake-shape records
 *     'fields'      => [ field_key => {
 *                          name,              // column header
 *                          data_path,         // dot-notation path into the record
 *                          element?,          // 'links' | 'org' | 'tags'
 *                                             //  | 'array_lookup_field' | (none)
 *                          url?,              // base URL (for 'links')
 *                          url_params_data_paths?, // path to value appended to URL
 *                          arrayData?,        // index→label map ('array_lookup_field')
 *                          scope?,            // 'feeds' | 'event' | ... (for 'tags')
 *                        }, ...
 *                     ],
 *     'description' => 'optional table caption',
 *   ];
 *
 * Token-driven CSS lives in dashboard.default.css under
 * "Index renderer". The renderer supports the subset of `element`
 * values the in-tree consumers actually use; new field types are
 * added one switch case at a time.
 */
$rows   = isset($data['data'])   ? $data['data']   : [];
$fields = isset($data['fields']) ? $data['fields'] : [];

if (empty($fields)) {
    echo '<div class="misp-list-empty">' . __('No columns declared.') . '</div>';
    return;
}

if (empty($rows)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

$baseurl = (Configure::read('MISP.baseurl') ?: rtrim(Router::url('/', true), '/'));

/**
 * Same URL safety contract as SimpleList: relative paths starting with
 * `/` (single slash), or absolute URLs on the same host as MISP.baseurl.
 */
$isSafeUrl = function ($url) use ($baseurl) {
    if (!is_string($url) || $url === '') return false;
    if ($url[0] === '/' && (!isset($url[1]) || $url[1] !== '/')) return true;
    if ($baseurl === '') return false;
    $baseHost = parse_url($baseurl, PHP_URL_HOST);
    $host     = parse_url($url, PHP_URL_HOST);
    return $baseHost && $host && strcasecmp($baseHost, $host) === 0;
};

/**
 * Dot-notation getter using Cake's Hash::get (already loaded by the
 * controller flow). Returns null on missing keys without raising.
 */
$pluck = function ($row, $path) {
    if (!is_string($path) || $path === '') return null;
    return Hash::get($row, $path);
};

/**
 * Render a single cell. The `element` field determines the dispatch;
 * unknown elements fall through to the scalar path (escaped value).
 */
$renderCell = function ($row, $field) use ($pluck, $isSafeUrl, $baseurl) {
    $element = isset($field['element']) ? $field['element'] : null;
    $value   = $pluck($row, isset($field['data_path']) ? $field['data_path'] : '');

    switch ($element) {
        case 'links':
            // Linkified id-like cell. Base URL + suffix from url_params_data_paths.
            // Only the scalar string-path case is supported here (matches all
            // in-tree consumers); the v1 element supports array-of-paths but
            // none of the dashboard widgets use that shape today.
            $url = isset($field['url']) ? (string)$field['url'] : '';
            if (!empty($field['url_params_data_paths']) && is_string($field['url_params_data_paths'])) {
                $suffix = $pluck($row, $field['url_params_data_paths']);
                if ($suffix !== null && $suffix !== '') {
                    $url .= '/' . rawurlencode((string)$suffix);
                }
            }
            $text = ($value === null || $value === '') ? '—' : (string)$value;
            if ($url !== '' && $isSafeUrl($url)) {
                return sprintf(
                    '<a class="misp-index-link" href="%s">%s</a>',
                    h($url),
                    h($text)
                );
            }
            return h($text);

        case 'org':
            // $value here is the Org/Orgc sub-record dict (data_path
            // typically points at `Orgc` or `Organisation`). Render as
            // a single link; logo support is intentionally omitted —
            // v2's compact widget body prefers text-only org chips.
            if (!is_array($value)) {
                return $value === null ? '' : h((string)$value);
            }
            $orgName = isset($value['name']) ? (string)$value['name'] : '';
            if ($orgName === '') return '';
            $orgId   = isset($value['id']) ? (string)$value['id'] : '';
            $orgUuid = isset($value['uuid']) ? (string)$value['uuid'] : '';
            $key     = $orgId !== '' ? $orgId : $orgUuid;
            if ($key === '') {
                return h($orgName);
            }
            $orgUrl = $baseurl . '/organisations/view/' . rawurlencode($key);
            if (!$isSafeUrl($orgUrl)) {
                return h($orgName);
            }
            return sprintf(
                '<a class="misp-index-link" href="%s">%s</a>',
                h($orgUrl),
                h($orgName)
            );

        case 'tags':
            // $value is an array of EventTag-shaped records, each with
            // a nested Tag dict carrying `name` and `colour`. Render as
            // static colored pills; tag modify / collection UI from v1
            // is deliberately omitted (read-only widget surface).
            if (!is_array($value) || empty($value)) return '';
            $chips = [];
            foreach ($value as $eventTag) {
                $tag = isset($eventTag['Tag']) && is_array($eventTag['Tag'])
                    ? $eventTag['Tag']
                    : (is_array($eventTag) ? $eventTag : []);
                $name = isset($tag['name']) ? (string)$tag['name'] : '';
                if ($name === '') continue;
                $colour = isset($tag['colour']) ? (string)$tag['colour'] : '';
                // Sanitize colour to #rrggbb / #rgb to avoid arbitrary
                // style injection; fallback to the muted CSS token.
                $style = '';
                if ($colour !== '' && preg_match('/^#[0-9A-Fa-f]{3}([0-9A-Fa-f]{3})?$/', $colour)) {
                    $style = sprintf(' style="background:%s;color:%s"',
                        h($colour),
                        _idxContrastColour($colour)
                    );
                }
                $chips[] = sprintf(
                    '<span class="misp-index-tag"%s>%s</span>',
                    $style,
                    h($name)
                );
            }
            return implode(' ', $chips);

        case 'array_lookup_field':
            // Discrete enum-ish value rendered through an arrayData
            // lookup. Matches EventStreamWidget's `analysis` field.
            $arr = isset($field['arrayData']) && is_array($field['arrayData'])
                ? $field['arrayData'] : [];
            if (!array_key_exists((int)$value, $arr)) {
                return h((string)$value);
            }
            return h((string)$arr[(int)$value]);

        default:
            // Scalar fallback. Arrays/objects don't make sense in a
            // single cell; render an inline JSON hint for debuggability.
            if (is_array($value)) {
                return '<em class="misp-index-muted">' . h('[array]') . '</em>';
            }
            if ($value === null || $value === '') return '';
            return h((string)$value);
    }
};

/**
 * Pick a readable text colour (white or near-black) for a given hex
 * background. Same heuristic as the v1 tagSimple element.
 */
if (!function_exists('_idxContrastColour')) {
    function _idxContrastColour($hex) {
        $h = ltrim($hex, '#');
        if (strlen($h) === 3) {
            $h = $h[0].$h[0].$h[1].$h[1].$h[2].$h[2];
        }
        if (strlen($h) !== 6) return '#1d2025';
        $r = hexdec(substr($h, 0, 2));
        $g = hexdec(substr($h, 2, 2));
        $b = hexdec(substr($h, 4, 2));
        // Perceived luminance (Rec. 601).
        $y = 0.299 * $r + 0.587 * $g + 0.114 * $b;
        return $y > 160 ? '#1d2025' : '#ffffff';
    }
}

if (!empty($data['description'])) {
    echo '<div class="misp-index-description">' . h($data['description']) . '</div>';
}

echo '<div class="misp-index">';
echo '<table class="misp-index-table">';
echo '<thead><tr>';
foreach ($fields as $field) {
    $label = isset($field['name']) ? (string)$field['name'] : '';
    echo '<th class="misp-index-th">' . h($label) . '</th>';
}
echo '</tr></thead>';

echo '<tbody>';
foreach ($rows as $row) {
    echo '<tr class="misp-index-tr">';
    foreach ($fields as $field) {
        echo '<td class="misp-index-td">' . $renderCell($row, $field) . '</td>';
    }
    echo '</tr>';
}
echo '</tbody>';

echo '</table>';
echo '</div>';
