<?php
$uid       = $data['User']['id'];
$adminView = !empty($admin_view);

$actions = [];


if ($adminView) {
    $actions[] = [
        'url'     => "$baseurl/admin/users/edit/$uid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/users/edit/$uid');",
        'icon'    => 'fas fa-pen-to-square',
        'label'   => __('Edit user'),
    ];
} else {
    $actions[] = [
        'url'     => "$baseurl/users/edit",
        'onclick' => "event.preventDefault(); openModal('$baseurl/users/edit');",
        'icon'    => 'fas fa-pen-to-square',
        'label'   => __('Edit profile'),
    ];
}

// Send email (admin only)
if ($adminView) {
    $actions[] = [
        'url'     => "$baseurl/admin/users/quickEmail/$uid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/users/quickEmail/$uid');",
        'icon'    => 'fas fa-envelope',
        'label'   => __('Send email to user'),
    ];
}

$actions[] = [
    'url'   => "$baseurl/users/view/$uid.json",
    'icon'  => 'fas fa-download',
    'label' => __('Download profile'),
];


$logsUrl = Configure::read('MISP.log_new_audit')
    ? "$baseurl/admin/audit_logs/index/model:User/model_id:$uid"
    : "$baseurl/admin/logs?model=User&model_id=$uid";
$actions[] = [
    'url'   => $logsUrl,
    'icon'  => 'fas fa-clipboard-list',
    'label' => __('Review user logs'),
];


$actions[] = [
    'url'   => "$baseurl/users/view_login_history/$uid",
    'icon'  => 'fas fa-right-to-bracket',
    'label' => __('Review user logins'),
];

// Delete (site admins, admin view only)
if ($adminView && !empty($isSiteAdmin)) {
    $actions[] = [
        'url'     => "$baseurl/admin/users/delete/$uid",
        'onclick' => "event.preventDefault(); openModal('$baseurl/admin/users/delete/$uid', 'sm');",
        'icon'    => 'fas fa-trash',
        'label'   => __('Delete user'),
        'danger'  => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);
