<?php
/*
 * Day-grouped timeline built server-side from the paginated $list.
 * Filtering/searching goes through the controller's named-param harvesting.
 */
App::uses('AuditLog', 'Model');

$this->set('headerTitle', __('Audit logs'));
$this->set('headerDescription', __('Chronological record of changes made to objects across MISP.'));

$actionOptions = ['' => __('All actions')] + (isset($actions) ? $actions : []);
$modelOptions  = ['' => __('All models')];
foreach (($models ?? []) as $m) {
    $modelOptions[$m] = $m;
}

$filterFields = [
    [
        'name' => 'model_title', 'label' => __('Title contains'), 'type' => 'text',
        'placeholder' => __('Search on this page...'), 'col' => 6,
    ],
    [
        'name' => 'action', 'label' => __('Action'), 'type' => 'select',
        'options' => $actionOptions, 'col' => 3,
    ],
    [
        'name' => 'model', 'label' => __('Model'), 'type' => 'select',
        'options' => $modelOptions, 'col' => 3,
    ],
    [
        'name' => 'model_id', 'label' => __('Model ID'), 'type' => 'number', 'col' => 3,
    ],
    [
        'name' => 'event_id', 'label' => __('Event ID'), 'type' => 'number', 'col' => 3,
    ],
    [
        'name' => 'user', 'label' => __('User'), 'type' => 'text',
        'placeholder' => __('ID, e-mail or SYSTEM'), 'col' => 3,
    ],
    [
        'name' => 'org', 'label' => __('Organisation'), 'type' => 'text',
        'placeholder' => __('ID, UUID or name'), 'col' => 3,
    ],
    [
        'name' => 'ip', 'label' => __('IP'), 'type' => 'text', 'col' => 3,
    ],
    [
        'name' => 'authkey_id', 'label' => __('Auth key ID'), 'type' => 'number', 'col' => 3,
    ],
    [
        'name' => 'request_type', 'label' => __('Request type'), 'type' => 'select',
        'options' => ['' => __('Any'), 0 => __('Browser'), 1 => __('API'), 2 => __('CLI / background job')],
        'col' => 3,
    ],
    [
        'name' => 'created', 'label' => __('Created after'), 'type' => 'date', 'col' => 3,
        'help' => __('Date or relative delta (e.g. 7d)'),
    ],
];

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
        $userLink = $baseurl . '/admin/users/view/' . h($item['User']['id']);
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

<div class="container-fluid">

    <?= $this->element('Logs/filter_card', [
        'item_url'      => '/admin/audit_logs',
        'search'        => ['placeholder' => __('Filter this page…')],
        'fields'        => $filterFields,
        'pager_element' => 'Logs/pager_prevnext',
    ]) ?>

    <?= $this->element('Logs/timeline', [
        'entries'    => $entries,
        'title'      => __('Audit history'),
        'icon'       => 'fas fa-history',
        'empty_text' => __('No audit log entries match your filters.'),
    ]) ?>

    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <?= $this->element('genericElementsBS5/IndexTable/pagination') ?>
        </div>
    </div>

</div>
