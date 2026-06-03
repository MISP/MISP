<?php
/**
 * OrgsPictures renderer (dashboard v2).
 *
 * Renders a grid of organisation logos for widgets that declare
 * `$render = 'OrgsPictures'` (OrgsContributorLastMonthWidget,
 * OrgsUsingMitreWidget, OrgsUsingObjectsWidget — all derivatives of
 * OrgsContributorsGeneric).
 *
 * Expected $data shape: flat array of Cake-shape Organisation records
 *   [ {Organisation: {id, name, uuid, ...}}, ... ]
 *
 * Each cell: clickable link to /organisations/view/<id>. If the org
 * has a logo (`app/files/img/orgs/<id|name|uuid>.<png|svg>`) — same
 * resolution order as OrgImgHelper::findOrgImage — the cell renders
 * an `<img src="/organisations/getOrgLogo/<id>">`; otherwise a
 * letter-chip fallback with the org's first character.
 *
 * Why not the OrgImg helper:
 *   v2 renderers stick to plain PHP + Hash::get / h / __ /
 *   Configure::read. OrgImgHelper inlines image data via
 *   ImageHelper::base64 (200KB+ per render for 20 orgs) and is
 *   marked @deprecated. The inline file_exists check matches the
 *   helper's logic exactly without the data-URL bloat — the browser
 *   caches the per-org logo URL across widget renders.
 *
 * v1 used `target="_blank"` to open org views in a new tab; v2
 * matches the rest of the dashboard's same-tab idiom (Index, Button,
 * SimpleList all navigate in-tab).
 *
 * Token-driven CSS lives in dashboard.default.css under
 * "OrgsPictures renderer".
 */
$orgs = is_array($data) ? $data : array();

if (empty($orgs)) {
    echo '<div class="misp-list-empty">' . __('No organisations to show.') . '</div>';
    return;
}

$baseurl = (string)Configure::read('MISP.baseurl');
$imgDir  = APP . 'files' . DS . 'img' . DS . 'orgs' . DS;

/**
 * Resolve an org's logo asset file name on disk (or null). Matches
 * OrgImgHelper::findOrgImage's lookup order: id → name → uuid,
 * each tried as .png then .svg.
 */
$findLogo = function (array $org) use ($imgDir) {
    foreach (array('id', 'name', 'uuid') as $field) {
        if (!isset($org[$field]) || $org[$field] === '') continue;
        foreach (array('png', 'svg') as $ext) {
            if (file_exists($imgDir . $org[$field] . '.' . $ext)) {
                return true;
            }
        }
    }
    return false;
};

echo '<div class="misp-orgs-grid">';
foreach ($orgs as $org) {
    if (empty($org['Organisation'])) continue;
    $o    = $org['Organisation'];
    $id   = isset($o['id'])   ? (string)$o['id']   : '';
    $name = isset($o['name']) ? (string)$o['name'] : '';
    if ($id === '' && $name === '') continue;

    $hasLogo = $findLogo($o);
    $href    = $baseurl . '/organisations/view/' . rawurlencode($id !== '' ? $id : $name);

    echo '<a class="misp-orgs-cell" href="' . h($href) . '" title="' . h($name) . '">';
    if ($hasLogo && $id !== '') {
        printf(
            '<img class="misp-orgs-logo" src="%s/organisations/getOrgLogo/%s" alt="%s" width="48" height="48" loading="lazy">',
            h($baseurl),
            h($id),
            h($name)
        );
    } else {
        $initial = $name !== '' ? mb_strtoupper(mb_substr($name, 0, 1, 'UTF-8'), 'UTF-8') : '?';
        echo '<span class="misp-orgs-chip" aria-hidden="true">' . h($initial) . '</span>';
        echo '<span class="misp-orgs-srlabel">' . h($name) . '</span>';
    }
    echo '</a>';
}
echo '</div>';
