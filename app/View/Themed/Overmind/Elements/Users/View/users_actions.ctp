<?php
$uid       = $data['User']['id'];
$adminView = !empty($admin_view);

$actions = [];


if ($adminView) {
    $actions[] = [
        'url'     => "$baseurl/admin/users/edit/$uid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/users/edit/$uid');",
        'icon'    => 'fas fa-pen',
        'label'   => __('Edit user'),
        'short'   => __('Edit'),
    ];
} else {
    $actions[] = [
        'url'     => "$baseurl/users/edit",
        'onclick' => "event.preventDefault(); openModal('$baseurl/users/edit');",
        'icon'    => 'fas fa-pen',
        'label'   => __('Edit profile'),
        'short'   => __('Edit'),
    ];
}

// Send email (admin only)
if ($adminView) {
    $actions[] = [
        'url'     => "$baseurl/admin/users/quickEmail/$uid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/users/quickEmail/$uid');",
        'icon'    => 'fas fa-envelope',
        'label'   => __('Send email to user'),
        'short'   => __('Email'),
    ];
}

$actions[] = [
    'url'   => "$baseurl/users/view/$uid.json",
    'icon'  => 'fas fa-download',
    'label' => __('Download profile'),
    'short' => __('Download'),
];


$logsUrl = Configure::read('MISP.log_new_audit')
    ? "$baseurl/admin/audit_logs/index/model:User/model_id:$uid"
    : "$baseurl/admin/logs?model=User&model_id=$uid";
$actions[] = [
    'url'   => $logsUrl,
    'icon'  => 'fas fa-clipboard-list',
    'label' => __('Review user logs'),
    'short' => __('Logs'),
];


$actions[] = [
    'url'   => "$baseurl/users/view_login_history/$uid",
    'icon'  => 'fas fa-right-to-bracket',
    'label' => __('Review user logins'),
    'short' => __('Logins'),
];

// Delete (site admins, admin view only)
if ($adminView && !empty($isSiteAdmin)) {
    $actions[] = [
        'url'     => "$baseurl/admin/users/delete/$uid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/users/delete/$uid', 'md');",
        'icon'    => 'fas fa-trash',
        'label'   => __('Delete user'),
        'danger'  => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_launch_bar', [
    'actions' => $actions,
]);
