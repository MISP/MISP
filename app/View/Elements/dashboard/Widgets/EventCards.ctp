<?php
/**
 * EventCards renderer (dashboard v2, analyst track — AD-W6 / AD-08).
 *
 * Flat, reverse-chronological event cards for the analyst event stream.
 * Consumes the EventStreamWidget `fetchEvent` payload verbatim — the same
 *   [ 'data' => [ <event record>, ... ], 'fields' => [...] ]
 * shape the Index renderer gets — but IGNORES `fields` (an Index column
 * concept): cards have a fixed, curated anatomy. Read-only (no in-body
 * controls — AD-08 Fork B); filter / scope is driven by the dashboard
 * toolbar canonical bulk-edit, exactly as the parent Index render is.
 *
 * Card anatomy (per AD-08 / the accepted mockup):
 *   row 1 = threat-level dot (colour by Event.threat_level_id) + label ·
 *           Orgc.name · relative time (Event.timestamp) · #id (→ event view)
 *   row 2 = Event.info (truncated)
 *   row 3 = tag chips (coloured, capped + "+N more") + attribute count
 *
 * The threat label + dot colour are derived from `Event.threat_level_id`
 * (1=High / 2=Medium / 3=Low / 4=Undefined) so the card never depends on
 * the optional ThreatLevel association being hydrated. The dot colour maps
 * to MISP's established threat-level palette through dashboard semantic
 * tokens (High→danger, Medium→info, Low→success, Undefined→muted), keeping
 * it theme-independent — the midnight overlay retones it via --misp-dash-*.
 *
 * No inline styles / hardcoded colours except the data-driven tag-chip
 * colours (same posture as Index.ctp's chips): visuals come from the
 * token-driven .misp-eventcards-* rules in dashboard.default.css. Reuses
 * Index.ctp's tag-chip contrast helper (`_idxContrastColour`), guard-defined
 * identically below so the card renders standalone when no Index widget
 * shares the page.
 */
$rows = isset($data['data']) ? $data['data'] : [];

if (empty($rows)) {
    echo '<div class="misp-list-empty">' . __('No events match.') . '</div>';
    return;
}

$baseurl = (Configure::read('MISP.baseurl') ?: rtrim(Router::url('/', true), '/'));

/**
 * Same URL safety contract as Index.ctp / SimpleList: relative paths
 * starting with a single `/`, or absolute URLs on MISP.baseurl's host.
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
 * threat_level_id → [css-modifier, human label]. Unknown / missing ids
 * fall through to the "undefined" bucket (the same way MISP treats an
 * absent threat level).
 */
$threatMap = [
    1 => ['high',      __('High')],
    2 => ['medium',    __('Medium')],
    3 => ['low',       __('Low')],
    4 => ['undefined', __('Undefined')],
];

/**
 * Compact relative time ("5m ago", "3h ago", "2d ago", …) from a unix
 * timestamp, plus an absolute ISO string for the hover tooltip. Returns
 * ['', ''] for a missing / non-positive timestamp.
 */
$relativeTime = function ($ts) {
    $ts = (int)$ts;
    if ($ts <= 0) return ['', ''];
    $diff = time() - $ts;
    if ($diff < 0) $diff = 0;
    $units = [
        [31536000, 'y'],
        [2592000,  'mo'],
        [604800,   'w'],
        [86400,    'd'],
        [3600,     'h'],
        [60,       'm'],
    ];
    foreach ($units as $unit) {
        if ($diff >= $unit[0]) {
            $n = (int)floor($diff / $unit[0]);
            return [$n . $unit[1] . ' ' . __('ago'), date('c', $ts)];
        }
    }
    return [__('just now'), date('c', $ts)];
};

/**
 * Truncate Event.info to a readable card length, multibyte-safe, with an
 * ellipsis when clipped.
 */
$truncate = function ($s, $len = 160) {
    $s = (string)$s;
    if (function_exists('mb_strlen')) {
        if (mb_strlen($s) <= $len) return $s;
        return rtrim(mb_substr($s, 0, $len)) . '…';
    }
    if (strlen($s) <= $len) return $s;
    return rtrim(substr($s, 0, $len)) . '…';
};

/**
 * Pick a readable text colour for a given hex background — mirrors
 * Index.ctp's helper exactly. Guarded so whichever renderer loads first
 * defines it; the bodies are identical, so order never matters.
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
        $y = 0.299 * $r + 0.587 * $g + 0.114 * $b;
        return $y > 160 ? '#1d2025' : '#ffffff';
    }
}

$tagCap = 5;

echo '<div class="misp-eventcards-list">';
foreach ($rows as $ev) {
    $e = isset($ev['Event']) && is_array($ev['Event']) ? $ev['Event'] : [];

    // --- threat level (dot colour + label) ---
    $tlid = isset($e['threat_level_id']) ? (int)$e['threat_level_id'] : 0;
    $threat = isset($threatMap[$tlid]) ? $threatMap[$tlid] : $threatMap[4];

    // --- org / time / id ---
    $orgName = isset($ev['Orgc']['name']) ? (string)$ev['Orgc']['name'] : '';
    list($timeText, $timeTitle) = $relativeTime(isset($e['timestamp']) ? $e['timestamp'] : 0);
    $id = isset($e['id']) ? (string)$e['id'] : '';

    // Row 1 left cluster: dot + threat label, then org, then time, each
    // separated by a "·". #id is pushed to the right (margin-left:auto).
    $left = sprintf(
        '<span class="misp-eventcards-dot misp-eventcards-dot--%s" title="%s"></span>'
        . '<span class="misp-eventcards-threat">%s</span>',
        h($threat[0]),
        h($threat[1]),
        h($threat[1])
    );
    if ($orgName !== '') {
        $left .= '<span class="misp-eventcards-sep">&middot;</span>'
            . '<span class="misp-eventcards-org">' . h($orgName) . '</span>';
    }
    if ($timeText !== '') {
        $left .= '<span class="misp-eventcards-sep">&middot;</span>'
            . sprintf('<span class="misp-eventcards-time" title="%s">%s</span>',
                h($timeTitle), h($timeText));
    }

    // Optional overlap badge (analyst track — AD-W8 / OverlapWithMyOrgWidget).
    // Present only when the handler set the `_analyst_overlap` per-record key
    // (the count of the viewer's-org events this candidate correlates to);
    // absent on the plain Event Card Stream (W6), so this card stays
    // unchanged there. The badge text is the AD-W8 wording.
    $overlap = isset($ev['_analyst_overlap']) ? (int)$ev['_analyst_overlap'] : 0;
    if ($overlap > 0) {
        $left .= sprintf(
            '<span class="misp-eventcards-overlap" title="%s">%s</span>',
            h(__('This event correlates with events your organisation created')),
            h(sprintf(__('overlaps %d of your events'), $overlap))
        );
    }

    $idHtml = '';
    if ($id !== '') {
        $eventUrl = $baseurl . '/events/view/' . rawurlencode($id);
        $idLabel = '#' . $id;
        if ($isSafeUrl($eventUrl)) {
            $idHtml = sprintf('<a class="misp-eventcards-id" href="%s">%s</a>',
                h($eventUrl), h($idLabel));
        } else {
            $idHtml = '<span class="misp-eventcards-id">' . h($idLabel) . '</span>';
        }
    }

    $row1 = '<div class="misp-eventcards-row1">' . $left . $idHtml . '</div>';

    // --- row 2: info (truncated) ---
    $info = isset($e['info']) ? $truncate($e['info']) : '';
    $row2 = $info !== ''
        ? '<div class="misp-eventcards-info">' . h($info) . '</div>'
        : '';

    // --- row 3: tag chips (capped + "+N more") + attribute count ---
    $validTags = [];
    if (!empty($ev['EventTag']) && is_array($ev['EventTag'])) {
        foreach ($ev['EventTag'] as $et) {
            $tag = isset($et['Tag']) && is_array($et['Tag']) ? $et['Tag'] : [];
            $name = isset($tag['name']) ? (string)$tag['name'] : '';
            if ($name === '') continue;
            $validTags[] = $tag;
        }
    }
    $chips = [];
    foreach (array_slice($validTags, 0, $tagCap) as $tag) {
        $name = (string)$tag['name'];
        $colour = isset($tag['colour']) ? (string)$tag['colour'] : '';
        $style = '';
        if ($colour !== '' && preg_match('/^#[0-9A-Fa-f]{3}([0-9A-Fa-f]{3})?$/', $colour)) {
            $style = sprintf(' style="background:%s;color:%s"',
                h($colour), _idxContrastColour($colour));
        }
        $chips[] = sprintf('<span class="misp-eventcards-tag"%s>%s</span>', $style, h($name));
    }
    $overflow = count($validTags) - count($chips);
    if ($overflow > 0) {
        $chips[] = sprintf('<span class="misp-eventcards-more">%s</span>',
            h(sprintf(__('+%d more'), $overflow)));
    }
    $tagsHtml = !empty($chips)
        ? '<div class="misp-eventcards-tags">' . implode('', $chips) . '</div>'
        : '';

    $attrCount = isset($e['attribute_count']) ? (int)$e['attribute_count'] : 0;
    $attrHtml = sprintf(
        '<span class="misp-eventcards-attrcount" title="%s">%s %s</span>',
        h(__('Attributes')),
        number_format($attrCount),
        h(__n('attr', 'attrs', $attrCount))
    );

    $row3 = ($tagsHtml !== '' || $attrHtml !== '')
        ? '<div class="misp-eventcards-row3">' . $tagsHtml . $attrHtml . '</div>'
        : '';

    echo '<div class="misp-eventcards-card">' . $row1 . $row2 . $row3 . '</div>';
}
echo '</div>';
