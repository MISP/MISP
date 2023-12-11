<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Noticelist view',
        'data' => $data,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'Noticelist.id'
            ],
            [
                'key' => __('Name'),
                'path' => 'Noticelist.name'
            ],
            [
                'key' => __('Version'),
                'path' => 'Noticelist.version'
            ],
            [
                'key' => __('Expanded Name'),
                'path' => 'Noticelist.expanded_name'
            ],
            [
                'key' => __('Ref'),
                'path' => 'Noticelist.ref',
                'type' => 'links',
            ],
            [
                'key' => __('Geographical Area'),
                'type' => 'custom',
                'function' => function (array $data) {
                    return implode('<br>', array_map('h', $data['Noticelist']['geographical_area']));
                }
            ],
            [
                'key' => __('Enabled'),
                'path' => 'Noticelist.enabled',
                'type' => 'boolean'
            ]
        ],
        'children' => [
            [
                'url' => '/noticelists/preview_entries/{{0}}/',
                'url_params' => ['Noticelist.id'],
                'title' => __('Values'),
                'elementId' => 'preview_entries_container'
            ]
        ]
    ]
);
