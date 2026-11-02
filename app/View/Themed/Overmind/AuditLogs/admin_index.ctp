<?php
/*
 * Day-grouped timeline built server-side from the paginated $list
 * (Elements/AuditLogs/log_index).
 */

$this->set('headerTitle', __('Audit logs'));
$this->set('headerDescription', __('Chronological record of changes made to objects across MISP.'));

$actionOptions = ['' => __('All actions')] + (isset($actions) ? $actions : []);
$modelOptions  = ['' => __('All models')];
foreach (($models ?? []) as $m) {
    $modelOptions[$m] = $m;
}

$what = __('What');
$who = __('Who');
$filterFields = [
    [
        'name' => 'model_title', 'label' => __('Title contains'), 'type' => 'text',
        'placeholder' => __('e.g. an event or attribute name'), 'group' => $what,
    ],
    [
        'name' => 'action', 'label' => __('Action'), 'type' => 'select',
        'options' => $actionOptions, 'group' => $what,
    ],
    [
        'name' => 'model', 'label' => __('Model'), 'type' => 'select',
        'options' => $modelOptions, 'group' => $what,
    ],
    [
        'name' => 'model_id', 'label' => __('Model ID'), 'type' => 'number',
        'placeholder' => __('e.g. 42'), 'group' => $what,
    ],
    [
        'name' => 'event_id', 'label' => __('Event ID'), 'type' => 'number',
        'placeholder' => __('e.g. 2178'), 'group' => $what,
    ],
    [
        'name' => 'user', 'label' => __('User'), 'type' => 'text',
        'placeholder' => __('ID, e-mail or SYSTEM'), 'group' => $who,
    ],
    [
        'name' => 'org', 'label' => __('Organisation'), 'type' => 'text',
        'placeholder' => __('ID, UUID or name'), 'group' => $who,
    ],
    [
        'name' => 'ip', 'label' => __('IP'), 'type' => 'text',
        'placeholder' => __('e.g. 10.0.0.1'), 'group' => $who,
    ],
    [
        'name' => 'authkey_id', 'label' => __('Auth key ID'), 'type' => 'number',
        'placeholder' => __('e.g. 7'), 'group' => $who,
    ],
    [
        'name' => 'request_type', 'label' => __('Request type'), 'type' => 'select',
        'options' => ['' => __('Any'), 0 => __('Browser'), 1 => __('API'), 2 => __('CLI / background job')],
        'group' => $who,
    ],
    [
        'name' => 'created', 'label' => __('Created'), 'type' => 'date', 'group' => __('When'),
    ],
];

echo $this->element('AuditLogs/log_index', [
    'list'       => $list ?? [],
    'fields'     => $filterFields,
    'scope'      => '/admin/audit_logs',
    'item_url'   => '/admin/audit_logs',
    'search'     => __('Search title, model, action, user, org, IP…'),
    'title'      => __('Audit history'),
    'empty_text' => __('No audit log entries match your filters.'),
]);
