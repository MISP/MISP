<?php
$fields = [
    [
        'key' => __('ID'),
        'path' => 'id'
    ],
    [
        'key' => __('Email'),
        'path' => 'email'
    ],
    [
        'type' => 'generic',
        'key' => __('Organisation'),
        'path' => 'Organisation.name',
        'url' => '/organisations/view/{{0}}',
        'url_vars' => 'Organisation.id'
    ],
    [
        'type' => 'generic',
        'key' => __('Role'),
        'path' => 'Role.name',
        'url' => '/roles/view/{{0}}',
        'url_vars' => 'Role.id'
    ],
    [
        'type' => 'email_notifications',
        'key' => __('Email notifications'),
        'path' => 'id'
    ],
    [
        'type' => 'boolean',
        'key' => __('Contact alert enabled'),
        'path' => 'contactalert',
        'pill' => true
    ],
    [
        'key' => __('NIDS Start SID'),
        'path' => 'nids_sid'
    ],
    [
        'key' => __('Terms accepted'),
        'path' => 'termsaccepted',
        'type' => 'boolean',
        'pill' => true
    ],
    [
        'key' => __('Must change password'),
        'path' => 'change_pw',
        'type' => 'boolean',
        'pill' => true
    ],
    [
        'key' => __('PGP key'),
        'path' => 'gpg_key',
        'type' => 'pgp_key'
    ],
    [
        'key' => __('S/MIME Public certificate'),
        'path' => 'smime'
    ],
    [
        'key' => __('Disabled'),
        'path' => 'disabled',
        'type' => 'boolean',
        'pill' => true
    ],
    
];
echo $this->element(
    '/genericElements/SingleViews/single_view',
    [
        'data' => $entity,
        'fields' => $fields,
        'title' => __('User {0}', h($entity->email)),
        'children' => [
            [
                'url' => '/AuthKeys/index?Users.id={{0}}',
                'url_params' => ['id'],
                'title' => __('Authentication keys')
            ],
            [
                'url' => '/Events/index?Users.id={{0}}',
                'url_params' => ['id'],
                'title' => __('Events')
            ]
        ]
    ]
);
