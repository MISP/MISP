<?php
/*
 * The event view's History tab (AuditLogsController::eventHistory): the
 * event's audit trail with the audit log index's filter bar and timeline
 * (Elements/AuditLogs/log_index), less what the event already fixes.
 */
$eventId = (int)$event['Event']['id'];
$canLinkUser = !empty($isSiteAdmin) || !empty($me['Role']['perm_admin']);

$what = __('What');
$who = __('Who');
$filterFields = [
    [
        'name' => 'model_title', 'label' => __('Title contains'), 'type' => 'text',
        'placeholder' => __('e.g. an attribute value or an object name'), 'group' => $what,
    ],
    [
        'name' => 'action', 'label' => __('Action'), 'type' => 'select',
        'options' => ['' => __('All actions')] + ($actions ?? []), 'group' => $what,
    ],
    [
        'name' => 'model', 'label' => __('Model'), 'type' => 'select',
        'options' => ['' => __('All models')] + array_combine($models ?? [], $models ?? []), 'group' => $what,
    ],
    [
        'name' => 'model_id', 'label' => __('Model ID'), 'type' => 'number',
        'placeholder' => __('e.g. 42'), 'group' => $what,
    ],
    [
        'name' => 'user', 'label' => __('User'), 'type' => 'text',
        'placeholder' => __('ID, e-mail or SYSTEM'), 'group' => $who,
        'requirement' => !empty($isSiteAdmin),
    ],
    [
        'name' => 'org', 'label' => __('Organisation'), 'type' => 'text',
        'placeholder' => __('ID, UUID or name'), 'group' => $who,
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
    'scope'      => '/audit_logs/eventHistory/' . $eventId,
    'item_url'   => '/audit_logs',
    'action'     => 'eventHistory',
    'search'     => !empty($isSiteAdmin)
        ? __('Search title, model, action, user, org…')
        : __('Search title, model, action, org…'),
    'title'      => __('History'),
    'empty_text' => __('No history entry matches your filters.'),
    'user_links' => $canLinkUser,
    'class'      => 'container-fluid px-0',
]);
