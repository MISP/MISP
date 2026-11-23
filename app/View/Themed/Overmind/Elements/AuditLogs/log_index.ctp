<?php
/*
 * An audit trail as the log indexes draw it: the log filter bar, then the
 * day-grouped timeline of its page and the pager. Shared by the audit log
 * index and the event view's History tab, which differ in their filters and
 * in the URL the bar drives.
 *
 * Expected variables:
 *  - $list        : paginated AuditLog rows (with action_human, model_link)
 *  - $fields      : the bar's filters, see Logs/filter_bar
 *  - $scope       : the [data-ifp-scope] key of the bar and its results
 *  - $item_url    : the bar's base path, e.g. '/admin/audit_logs'
 *  - $action      : optional action the bar drives (default 'index')
 *  - $search      : placeholder of the search box
 *  - $title       : the timeline card's title
 *  - $empty_text  : what the timeline says with no entry
 *  - $user_links  : link users to their admin page (default true)
 *  - $class       : the wrapper's classes (default 'container-fluid')
 */
App::uses('AuditLog', 'Model');
$userLinks = $user_links ?? true;

/* ── change-diff renderer (old ↦ new) ────────────────────────────────── */
$deleteSet = [
    AuditLog::ACTION_DELETE => 1, AuditLog::ACTION_SOFT_DELETE => 1,
    AuditLog::ACTION_REMOVE_GALAXY => 1, AuditLog::ACTION_REMOVE_GALAXY_LOCAL => 1,
    AuditLog::ACTION_REMOVE_TAG => 1, AuditLog::ACTION_REMOVE_TAG_LOCAL => 1,
];
$buildChange = function ($change, $action) use ($deleteSet) {
    if (!is_array($change) || empty($change)) {
        return '';
    }
    $enc = function ($v) {
        $s = json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($s === false) {
            $s = (string)$v;
        }
        if (mb_strlen($s) > 200) {
            $s = mb_substr($s, 0, 200) . '…';
        }
        return h($s);
    };
    $out = '';
    foreach ($change as $field => $val) {
        $out .= '<div><span class="fw-bold me-1">' . h($field) . ':</span>';
        if (isset($deleteSet[$action])) {
            $out .= '<span class="text-danger text-decoration-line-through" style="opacity:.85;">' . $enc($val) . '</span>';
        } elseif (is_array($val) && count($val) === 2 && array_keys($val) === [0, 1]) {
            $out .= '<span class="text-danger text-decoration-line-through" style="opacity:.85;">' . $enc($val[0]) . '</span>'
                 . '<span class="text-muted mx-1" style="font-size:.65rem;"><i class="fas fa-arrow-right"></i></span>'
                 . '<span class="text-success">' . $enc($val[1]) . '</span>';
        } else {
            $out .= '<span class="text-success">' . $enc($val) . '</span>';
        }
        $out .= '</div>';
    }
    return $out;
};

/* ── normalise the paginated rows into timeline entries ──────────────── */
$entries = [];
foreach (($list ?? []) as $item) {
    $al = $item['AuditLog'];

    // user
    $user = null;
    $userLink = null;
    if (isset($al['user_id']) && (int)$al['user_id'] === 0) {
        $user = __('SYSTEM');
    } elseif (!empty($item['User']['email'])) {
        $user = $item['User']['email'];
        $userLink = $userLinks ? $baseurl . '/admin/users/view/' . h($item['User']['id']) : null;
    } elseif (!empty($al['user_id'])) {
        $user = __('Deleted user #%s', $al['user_id']);
    }

    // org
    $org = null;
    $orgLink = null;
    if (!empty($item['Organisation']['name'])) {
        $org = $item['Organisation']['name'];
        if (!empty($item['Organisation']['id'])) {
            $orgLink = $baseurl . '/organisations/view/' . h($item['Organisation']['id']);
        }
    } elseif (!empty($al['org_id']) && (int)$al['org_id'] !== 0) {
        $org = __('Deleted org #%s', $al['org_id']);
    }

    // request badge
    $badge = null;
    if (isset($al['request_type']) && (int)$al['request_type'] === AuditLog::REQUEST_TYPE_CLI) {
        $badge = ['label' => __('CLI'), 'icon' => 'fas fa-terminal', 'title' => __('Action done by CLI or background job')];
    } elseif (isset($al['request_type']) && (int)$al['request_type'] === AuditLog::REQUEST_TYPE_API) {
        $keyTxt = !empty($al['authkey_id']) ? ' ' . __('by auth key #%s', $al['authkey_id']) : '';
        $badge = ['label' => __('API'), 'icon' => 'fas fa-cogs', 'title' => __('Action done through API') . $keyTxt];
    }

    $modelEyebrow = ($al['model'] ?? '');
    if (!empty($al['model_id'])) {
        $modelEyebrow .= ' #' . $al['model_id'];
    }
    $mainTitle = (isset($al['title']) && $al['title'] !== '') ? $al['title'] : ('#' . ($al['model_id'] ?? ''));

    $entries[] = [
        'created'       => $al['created'] ?? '',
        'action'        => $al['action'] ?? '',
        'action_label'  => $al['action_human'] ?? ($al['action'] ?? ''),
        'title'         => $mainTitle,
        'model'         => $modelEyebrow,
        'model_link'    => $al['model_link'] ?? null,
        'user'          => $user,
        'user_link'     => $userLink,
        'org'           => $org,
        'org_link'      => $orgLink,
        'request_badge' => $badge,
        'change_html'   => $buildChange($al['change'] ?? null, $al['action'] ?? ''),
    ];
}
?>

<div class="<?= h($class ?? 'container-fluid') ?>" data-ifp-scope="<?= h($scope) ?>">

    <?= $this->element('Logs/filter_bar', [
        'item_url' => $item_url,
        'action'   => $action ?? 'index',
        'search'   => ['placeholder' => $search],
        'fields'   => $fields,
        'rows'     => $entries,
        'pager'    => 'Logs/pager_prevnext',
    ]) ?>

    <!-- Swapped by the filter bar when filters apply (index-filters.js) -->
    <div id="log-index-results" class="index-results" data-ifp-results>
        <?= $this->element('Logs/timeline', [
            'entries'    => $entries,
            'title'      => $title,
            'icon'       => 'fas fa-history',
            'empty_text' => $empty_text,
        ]) ?>

        <?= $this->element('genericElementsBS5/IndexTable/pagination_bottom', [
            'rows' => count($entries),
            'pager' => 'Logs/pager_prevnext',
        ]) ?>
    </div>

</div>
