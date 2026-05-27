<?php
/**
 * UserList renderer (dashboard v2).
 *
 * A "people list" for widgets whose handler() returns a roster of users
 * (LoggedInUsersWidget first; reusable by any future user-listing widget).
 * Each user is a row with an avatar (the user's org logo, falling back to
 * an initials chip), a primary name line (email), a muted meta line
 * (org · role · …), and an optional right-aligned badge pill (e.g. live
 * session count). The whole row is a link to a per-user drilldown when one
 * is given.
 *
 * Data contract — a flat list of typed rows:
 *
 *   $data = [
 *     // Optional summary header (at most one, normally first):
 *     ['type' => 'header', 'value' => '3 users online · 7 sessions',
 *      'search' => true],                       // optional → client filter box
 *
 *     // A user row:
 *     ['type' => 'user',
 *      'name'  => 'alice@acme.test',          // primary line (raw)
 *      'meta'  => 'ACME Corp · Admin',         // muted secondary (raw)
 *      'badge' => 3,                           // optional pill (scalar)
 *      'muted' => false,                       // optional → dimmed row
 *      'org'   => ['id' => 5, 'name' => 'ACME Corp', 'uuid' => '…'],
 *                                              // optional → avatar logo
 *      'drilldown' => '/admin/users/view/5',   // optional (DD-03 gated)
 *      'action' => ['url' => '/dashboards/…',  // optional → per-row button
 *                   'label' => 'Invalidate sessions']],  //   (DD-03 gated)
 *
 *     // A full-width message (empty / error / unsupported states):
 *     ['type' => 'message', 'title' => 'Unsupported session engine',
 *      'value' => '…'],
 *   ];
 *
 * `search` (header) renders a filter input; user-list.module.mjs does the
 * client-side row filtering + re-applies the term across auto-refresh.
 * `action` (user) renders a sibling button carrying the URL — a <button>
 * can't nest in the row's drilldown <a>, so the avatar/name/badge area is
 * an inner link and the action button is its sibling. The module GET-loads
 * the URL as a confirm form in the side panel and POSTs it (DD-36).
 *
 * A row with no `type` but a `name` is treated as a user; otherwise as a
 * message. Drilldown URL safety is gated by DashboardURLValidator (DD-03):
 * unsafe / off-host URLs are dropped and the row renders un-linked.
 *
 * Escaping (DD-34): widget handler()s emit RAW strings — this renderer
 * h()s every interpolated value exactly once. Initials are derived here
 * from the (raw) name, never trusted from the widget.
 *
 * Avatar logo resolution mirrors OrgsPictures / OrgImgHelper::findOrgImage
 * (id → name → uuid, each .png then .svg under app/files/img/orgs/), served
 * via /organisations/getOrgLogo/<id> so the browser caches it across
 * renders instead of inlining a data-URL per row.
 *
 * No inline styles / hardcoded colours: visuals come from the token-driven
 * .misp-user-* rules in dashboard.default.css, so themes that only redefine
 * the --misp-dash-* tokens retone this for free. This renderer is NOT its
 * own scroll/size container — .misp-widget-body owns padding + overflow.
 */
App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

if (empty($data)) {
    echo '<div class="misp-user-message"><span class="misp-user-message-text">'
        . __('No data.') . '</span></div>';
    return;
}

$baseurl = (string)Configure::read('MISP.baseurl');
$imgDir  = APP . 'files' . DS . 'img' . DS . 'orgs' . DS;

/**
 * Does this org have a logo asset on disk? Same lookup order as
 * OrgImgHelper::findOrgImage: id → name → uuid, each .png then .svg.
 */
$hasLogo = function ($org) use ($imgDir) {
    if (empty($org) || !is_array($org)) {
        return false;
    }
    foreach (array('id', 'name', 'uuid') as $field) {
        if (empty($org[$field])) {
            continue;
        }
        foreach (array('png', 'svg') as $ext) {
            if (file_exists($imgDir . $org[$field] . '.' . $ext)) {
                return true;
            }
        }
    }
    return false;
};

/**
 * Derive an avatar initials chip from a (raw) name: up to two leading
 * letters/digits of the local part (before any @), upper-cased.
 */
$initials = function ($name) {
    $name = (string)$name;
    $at = strpos($name, '@');
    $local = ($at !== false) ? substr($name, 0, $at) : $name;
    if (preg_match_all('/[\p{L}\p{N}]/u', $local, $m) && !empty($m[0])) {
        return mb_strtoupper(implode('', array_slice($m[0], 0, 2)), 'UTF-8');
    }
    return '?';
};

// Per-row action glyph — a "log out" icon (door + exit arrow). Inline
// SVG, NOT FontAwesome: the dashboard layouts load different FA majors
// per theme, so FA classes are unreliable (cf. StatGlyph / DD-32).
$actionGlyph = '<svg class="misp-user-action-icon" viewBox="0 0 24 24" width="15" height="15"'
    . ' fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"'
    . ' stroke-linejoin="round" aria-hidden="true" focusable="false">'
    . '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>'
    . '<polyline points="16 17 21 12 16 7"/>'
    . '<line x1="21" y1="12" x2="9" y2="12"/>'
    . '</svg>';

$instanceId = isset($instance_id) ? (string)$instance_id : '';
echo '<div class="misp-user-list" data-misp-user-list data-misp-instance="'
    . h($instanceId) . '">';
foreach ($data as $row) {
    $type = isset($row['type']) ? $row['type']
        : (isset($row['name']) ? 'user' : 'message');

    if ($type === 'header') {
        echo '<div class="misp-user-header">'
            . '<span class="misp-user-dot" aria-hidden="true"></span>'
            . '<span class="misp-user-headtext">' . h($row['value'] ?? '') . '</span>'
            . '</div>';
        if (!empty($row['search'])) {
            // Client-side filter input; user-list.module.mjs wires it and
            // re-applies the term across the widget's auto-refresh.
            echo '<div class="misp-user-searchbar">'
                . '<input type="search" class="misp-user-search" data-misp-user-search'
                . ' placeholder="' . h(__('Filter users…')) . '"'
                . ' aria-label="' . h(__('Filter logged-in users')) . '" autocomplete="off">'
                . '</div>';
        }
        continue;
    }

    if ($type === 'message') {
        $title = !empty($row['title'])
            ? '<span class="misp-user-message-title">' . h($row['title']) . '</span>'
            : '';
        $text = isset($row['value'])
            ? '<span class="misp-user-message-text">' . h($row['value']) . '</span>'
            : '';
        echo '<div class="misp-user-message">' . $title . $text . '</div>';
        continue;
    }

    // ---- user row ----
    $name = (string)($row['name'] ?? '');
    $org  = isset($row['org']) && is_array($row['org']) ? $row['org'] : array();

    // Avatar: org logo when one exists on disk, else an initials chip.
    if ($hasLogo($org) && !empty($org['id'])) {
        $avatar = sprintf(
            '<img class="misp-user-logo" src="%s/organisations/getOrgLogo/%d" alt="%s" width="36" height="36" loading="lazy">',
            h($baseurl),
            (int)$org['id'],
            h(isset($org['name']) ? $org['name'] : '')
        );
    } else {
        $avatar = '<span class="misp-user-chip" aria-hidden="true">'
            . h($initials($name)) . '</span>';
    }

    $badge = '';
    if (isset($row['badge']) && $row['badge'] !== '' && !is_array($row['badge'])) {
        $badge = '<span class="misp-user-badge">' . h($row['badge']) . '</span>';
    }

    $main = sprintf(
        '<span class="misp-user-avatar">%s</span>'
        . '<span class="misp-user-body">'
        . '<span class="misp-user-name">%s</span>'
        . '<span class="misp-user-meta">%s</span>'
        . '</span>%s',
        $avatar,
        h($name),
        h($row['meta'] ?? ''),
        $badge
    );

    // The avatar/name/badge area is the drilldown link (or an inert div);
    // a per-row action button (invalidate sessions, DD-36) is its SIBLING
    // — a <button> can't live inside the <a>, and its click must not
    // trigger the row drilldown.
    $href = null;
    if (!empty($row['drilldown'])) {
        $href = DashboardURLValidator::validate($row['drilldown']);
    }
    $mainEl = ($href !== null)
        ? sprintf('<a class="misp-user-main" href="%s">%s</a>', h($href), $main)
        : sprintf('<div class="misp-user-main">%s</div>', $main);

    $action = '';
    if (!empty($row['action']['url'])) {
        $actionUrl = DashboardURLValidator::validate($row['action']['url']);
        if ($actionUrl !== null) {
            $label = !empty($row['action']['label'])
                ? $row['action']['label']
                : __('Invalidate sessions');
            $action = '<button type="button" class="misp-user-action"'
                . ' data-misp-user-action-url="' . h($actionUrl) . '"'
                . ' title="' . h($label) . '" aria-label="' . h($label) . '">'
                . $actionGlyph . '</button>';
        }
    }

    $cls = 'misp-user-row' . (!empty($row['muted']) ? ' misp-user-muted' : '');
    echo sprintf('<div class="%s">%s%s</div>', $cls, $mainEl, $action);
}
echo '</div>';
