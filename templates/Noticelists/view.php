<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => 'Noticelist view',
        'data' => $entity,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('Name'),
                'path' => 'name'
            ],
            [
                'key' => __('Version'),
                'path' => 'version'
            ],
            [
                'key' => __('Expanded Name'),
                'path' => 'expanded_name'
            ],
            [
                'key' => __('Ref'),
                'type' => 'custom',
                'function' => function ($entity) {
                    return implode('<br>', array_map('h', $entity->ref));
                }
            ],
            [
                'key' => __('Geographical Area'),
                'type' => 'custom',
                'function' => function ($entity) {
                    return implode('<br>', array_map('h', $entity->geographical_area));
                }
            ],
            [
                'key' => __('Enabled'),
                'path' => 'enabled',
                'type' => 'boolean'
            ]
        ],
        'children' => [
            [
                'url' => '/noticelists/preview_entries/{{0}}',
                'url_params' => ['id'],
                'title' => __('Values'),
                'elementId' => 'preview_entries_container'
            ]
        ]
    ]
);
