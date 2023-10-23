<?php
echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'light_paginator' => 1,
        'data' => $data,
        'fields' => [
            [
                'name' => __('Created'),
                'data_path' => 'AuditLog.created',
                'sort' => 'AuditLog.created',
                'class' => 'short',
                'element' => 'time'
            ],
            [
                'name' => __('User'),
                'data_path' => 'User.email',
                'sort' => 'User.email',
                'class' => 'short',
                'empty' => 'SYSTEM'
            ],
            [
                'name' => __('Organisation'),
                'data_path' => 'Organisation',
                'sort' => 'Organisation.name',
                'element' => 'org',
                'class' => 'short'
            ],
            [
                'name' => __('Action'),
                'data_path' => 'AuditLog.action_human',
                'sort' => 'AuditLog.action_human',
                'class' => 'short'
            ],
            [
                'name' => __('Model'),
                'data_path' => 'AuditLog',
                'element' => 'model',
                'class' => 'short'
            ],
            [
                'name' => __('Title'),
                'data_path' => 'AuditLog.title',
                'class' => 'limitedWidth'
            ],
            [
                'name' => __('Change'),
                'data_path' => 'AuditLog',
                'element' => 'custom_element',
                'element_path' => 'AuditLog/change'
            ]
        ],
        'title' => __('Audit logs for event #%s', intval($event['Event']['id'])),
        'persistUrlParams' => ['eventId', 'org']
    ]
]);
echo '</div>';
if (empty($ajax)) {
    echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
}
