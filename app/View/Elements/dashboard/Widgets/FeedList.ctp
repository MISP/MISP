<?php
/**
 * FeedList renderer (dashboard v2, analyst track — AD-17 / W10–W12).
 *
 * A reverse-chronological feed of "recently added" items, shared by the
 * three feed widgets: Recent Event Reports (W10), Recent Analyst Data
 * (W11) and Recently Added Galaxy Clusters (W12). Each row reads:
 *
 *   [icon]  TITLE                                                 →
 *           org · relative-time · context        [chip] [chip]
 *           "optional snippet / subtitle, truncated"
 *
 * Rows arrive PRE-SORTED by the widget (newest first); this renderer does
 * not re-order. Read-only (no in-body controls) — filter / scope rides the
 * dashboard toolbar, exactly like the Index / EventCards renders.
 *
 * Data contract — a flat list of row dicts (like Trending / StatGrid, so
 * the bare handler() return is the row list; no { data: … } wrapper):
 *
 *   $data = [
 *     [
 *       'title'     => string,        // REQUIRED primary line
 *       'icon'      => string|null,   // optional leading glyph — a
 *                                     //   FontAwesome icon NAME (e.g.
 *                                     //   'file-text-o', a Galaxy.icon),
 *                                     //   namespaced via the FA helper
 *       'org'       => string|null,   // optional — first meta segment
 *       'timestamp' => int|null,      // optional unix epoch → relative
 *                                     //   time ("5w ago"); ISO tooltip
 *       'context'   => string|null,   // optional meta segment (e.g.
 *                                     //   "Event #1842", "on Attribute")
 *       'chips'     => string[]|null, // optional small muted pills (e.g.
 *                                     //   target object type, galaxy type)
 *       'subtitle'  => string|null,   // optional snippet, template-truncated
 *       'drilldown' => string|null,   // optional link-out (whole row becomes
 *                                     //   a link, shows the → affordance);
 *                                     //   gated by DashboardURLValidator
 *     ],
 *     ...
 *   ];
 *
 * URL safety for `drilldown` is gated by DashboardURLValidator (DD-03) — an
 * unsafe URL is dropped and the row renders as plain (non-link) markup.
 *
 * No inline styles / hardcoded colours: visuals come from the token-driven
 * .misp-feedlist-* rules in dashboard.default.css, so the midnight theme
 * retones for free by only redefining the --misp-dash-* tokens.
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

if (empty($data) || !is_array($data)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

/**
 * Compact relative time ("5m ago", "3h ago", "2w ago", …) from a unix
 * timestamp, plus an absolute ISO string for the hover tooltip. Returns
 * ['', ''] for a missing / non-positive timestamp. (Same shape as the
 * EventCards helper; local to this element's render scope.)
 */
$relativeTime = function ($ts) {
    $ts = (int)$ts;
    if ($ts <= 0) {
        return ['', ''];
    }
    $diff = time() - $ts;
    if ($diff < 0) {
        $diff = 0;
    }
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
 * Truncate a string to a readable length, multibyte-safe, ellipsis when
 * clipped.
 */
$truncate = function ($s, $len) {
    $s = (string)$s;
    if (function_exists('mb_strlen')) {
        if (mb_strlen($s) <= $len) {
            return $s;
        }
        return rtrim(mb_substr($s, 0, $len)) . '…';
    }
    if (strlen($s) <= $len) {
        return $s;
    }
    return rtrim(substr($s, 0, $len)) . '…';
};

echo '<div class="misp-feedlist">';
foreach ($data as $row) {
    if (!is_array($row)) {
        continue;
    }
    $title = isset($row['title']) ? trim((string)$row['title']) : '';
    if ($title === '') {
        // A row with no primary line is malformed — skip it rather than
        // render an empty card.
        continue;
    }

    // --- leading glyph (optional): an icon NAME → namespaced FA class via
    //     the helper (getClass() h-escapes its output), the same path core
    //     uses for galaxy icons. ---
    $iconHtml = '';
    if (!empty($row['icon'])) {
        $iconHtml = sprintf(
            '<span class="misp-feedlist-icon"><i class="%s" aria-hidden="true"></i></span>',
            $this->FontAwesome->getClass((string)$row['icon'])
        );
    }

    // --- meta line: org · relative-time · context, then chips. Each
    //     segment is optional; a "·" separates only the segments that are
    //     present. ---
    $segments = [];
    if (!empty($row['org'])) {
        $segments[] = '<span class="misp-feedlist-org">' . h((string)$row['org']) . '</span>';
    }
    if (!empty($row['timestamp'])) {
        list($timeText, $timeTitle) = $relativeTime($row['timestamp']);
        if ($timeText !== '') {
            $segments[] = sprintf(
                '<span class="misp-feedlist-time" title="%s">%s</span>',
                h($timeTitle),
                h($timeText)
            );
        }
    }
    if (!empty($row['context'])) {
        $segments[] = '<span class="misp-feedlist-context">' . h((string)$row['context']) . '</span>';
    }
    $metaInner = implode('<span class="misp-feedlist-sep">&middot;</span>', $segments);

    // chips (optional small muted pills — target object type, galaxy type…)
    $chipsHtml = '';
    if (!empty($row['chips']) && is_array($row['chips'])) {
        foreach ($row['chips'] as $chip) {
            $chip = trim((string)$chip);
            if ($chip === '') {
                continue;
            }
            $chipsHtml .= '<span class="misp-feedlist-chip">' . h($chip) . '</span>';
        }
    }

    $metaHtml = '';
    if ($metaInner !== '' || $chipsHtml !== '') {
        $metaHtml = '<div class="misp-feedlist-meta">' . $metaInner
            . ($chipsHtml !== '' ? '<span class="misp-feedlist-chips">' . $chipsHtml . '</span>' : '')
            . '</div>';
    }

    // --- snippet (optional, truncated) ---
    $snippetHtml = '';
    if (!empty($row['subtitle'])) {
        $snip = $truncate($row['subtitle'], 140);
        if ($snip !== '') {
            $snippetHtml = '<div class="misp-feedlist-snippet">' . h($snip) . '</div>';
        }
    }

    $body = '<div class="misp-feedlist-body">'
        . '<div class="misp-feedlist-title">' . h($title) . '</div>'
        . $metaHtml
        . $snippetHtml
        . '</div>';

    // Whole row is a link when a safe drilldown URL is present (DD-03);
    // the → affordance is shown only then.
    $href = null;
    if (!empty($row['drilldown'])) {
        $href = DashboardURLValidator::validate((string)$row['drilldown']);
    }
    if ($href !== null) {
        echo sprintf(
            '<a class="misp-feedlist-item" href="%s">%s%s<span class="misp-feedlist-go" aria-hidden="true">&rarr;</span></a>',
            h($href),
            $iconHtml,
            $body
        );
    } else {
        echo sprintf(
            '<div class="misp-feedlist-item">%s%s</div>',
            $iconHtml,
            $body
        );
    }
}
echo '</div>';
