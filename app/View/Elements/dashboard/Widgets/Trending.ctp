<?php
/**
 * Trending renderer (dashboard v2, analyst track — AD-W1 / AD-01).
 *
 * A ranked-row list for "what is rising" widgets: each row is a value
 * (a CVE, threat actor, ATT&CK technique, …) shown with its volume and
 * its momentum. Rows arrive PRE-SORTED by the widget (volume desc); this
 * renderer does not re-rank. Per row:
 *
 *   [ label ……………………… <volume bar> ]  count  ▲/▼ delta
 *
 * The volume bar is a left-anchored fill behind the label, its width
 * proportional to the row's count over the largest count in the set, so
 * the ranking reads at a glance. The delta badge carries the AD-03
 * momentum signal — a floored % change vs the immediately-preceding equal
 * window (▲ = rising, success colour; ▼ = falling, danger colour). NOT a
 * BarChart: a bar chart can't carry the per-row delta badge cleanly
 * (AD-01). Sparklines are deferred polish (AD-01).
 *
 * Data contract — a flat list of row dicts (like SimpleList / StatGrid,
 * so the bare handler() return is the row list; no { data: … } wrapper):
 *
 *   $data = [
 *     [
 *       'label'     => string,       // REQUIRED display name
 *       'count'     => int,          // REQUIRED current-window distinct-event
 *                                    //   count; drives the bar + the number
 *       'delta'     => int|null,     // optional floored % change vs the prior
 *                                    //   equal window; >0 ▲ (success), <0 ▼
 *                                    //   (danger); null/absent/0 → no badge
 *       'badge'     => string|null,  // optional — overrides the numeric delta
 *                                    //   badge (e.g. 'NEW' for an item with no
 *                                    //   prior-window baseline); rising style
 *       'drilldown' => string|null,  // optional link-out (whole row becomes a
 *                                    //   link); gated by DashboardURLValidator
 *       'title'     => string|null,  // optional hover tooltip (e.g. synonyms)
 *       'icon'      => string|null,  // optional leading glyph — a FontAwesome
 *                                    //   icon NAME (e.g. 'user-secret'), as
 *                                    //   stored on a galaxy; namespaced via
 *                                    //   the FontAwesome helper. Absent for
 *                                    //   non-galaxy dimensions (e.g. CVEs).
 *     ],
 *     ...
 *   ];
 *
 * The leading per-row icon (above) is the galaxy-dimension extension (W3/W4):
 * the value arm (vulnerabilities) carries none, the galaxy arms (threat
 * actors, ATT&CK techniques) resolve a Galaxy.icon into it.
 *
 * URL safety for `drilldown` is gated by DashboardURLValidator (DD-03) —
 * an unsafe URL is dropped and the row renders as plain (non-link) markup.
 *
 * No inline styles / hardcoded colours: visuals come from the token-driven
 * .misp-trending-* rules in dashboard.default.css (so the midnight theme
 * retones for free by only redefining --misp-dash-* tokens). The single
 * inline value is the data-driven bar width, carried as the
 * --misp-trending-fill custom property — the bar's colour/height/shape all
 * stay in the stylesheet (same posture as Index.ctp's data-driven chips).
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

if (empty($data)) {
    echo '<div class="misp-list-empty">' . __('No data.') . '</div>';
    return;
}

// Largest count in the set scales every bar; guard against an all-zero /
// empty-count set so a row never divides by zero (then all bars read 0).
$maxCount = 0;
foreach ($data as $row) {
    $c = isset($row['count']) ? (int)$row['count'] : 0;
    if ($c > $maxCount) {
        $maxCount = $c;
    }
}

echo '<div class="misp-trending-list">';
foreach ($data as $row) {
    $label = (string)($row['label'] ?? '');
    $count = isset($row['count']) ? (int)$row['count'] : 0;

    // Bar width as a percentage of the top row's volume, clamped [0,100].
    $fill = $maxCount > 0 ? max(0, min(100, ($count * 100) / $maxCount)) : 0;
    // rtrim a trailing ".0" so common widths stay tidy ("50%" not "50.0%").
    $fillStr = rtrim(rtrim(sprintf('%.1f', $fill), '0'), '.') . '%';

    // Momentum badge: an explicit `badge` string (e.g. "NEW") wins and takes
    // the rising style; otherwise a non-zero `delta` renders as ▲/▼ + |%|.
    $badge = '';
    if (isset($row['badge']) && $row['badge'] !== '') {
        $badge = sprintf(
            '<span class="misp-trending-delta misp-trending-delta-up">%s</span>',
            h($row['badge'])
        );
    } elseif (!empty($row['delta'])) {
        $d = (int)$row['delta'];
        $cls = $d > 0 ? 'misp-trending-delta-up' : 'misp-trending-delta-down';
        $arrow = $d > 0 ? '&#9650;' : '&#9660;';   // ▲ / ▼
        $badge = sprintf(
            '<span class="misp-trending-delta %s"><span class="misp-trending-arrow">%s</span>%s%%</span>',
            $cls,
            $arrow,
            number_format(abs($d))
        );
    }

    // Optional leading glyph (galaxy dimensions): an icon NAME resolved to a
    // namespaced FA class by the helper (getClass() h-escapes its output) —
    // the same path core uses for galaxy icons. Empty for the value arm.
    $iconHtml = '';
    if (!empty($row['icon'])) {
        $iconHtml = sprintf(
            '<span class="misp-trending-icon"><i class="%s" aria-hidden="true"></i></span>',
            $this->FontAwesome->getClass((string)$row['icon'])
        );
    }

    $inner = sprintf(
        '<span class="misp-trending-bar" style="--misp-trending-fill:%s"></span>'
        . '%s'
        . '<span class="misp-trending-label">%s</span>'
        . '<span class="misp-trending-meta">'
        . '<span class="misp-trending-count">%s</span>%s</span>',
        h($fillStr),
        $iconHtml,
        h($label),
        number_format($count),
        $badge
    );

    $titleAttr = !empty($row['title']) ? ' title="' . h($row['title']) . '"' : '';

    // Whole row is a link when a safe drilldown URL is present (DD-03).
    $href = null;
    if (!empty($row['drilldown'])) {
        $href = DashboardURLValidator::validate($row['drilldown']);
    }
    if ($href !== null) {
        echo sprintf('<a class="misp-trending-row" href="%s"%s>%s</a>', h($href), $titleAttr, $inner);
    } else {
        echo sprintf('<div class="misp-trending-row"%s>%s</div>', $titleAttr, $inner);
    }
}
echo '</div>';
