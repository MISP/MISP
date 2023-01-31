<?php
echo $this->element(
    '/genericElements/SingleViews/single_view',
    [
        'data' => $entity,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => 'id'
            ],
            [
                'key' => __('Name'),
                'path' => '',
                'type' => 'tag',
            ],
            [
                'key' => __('Counter'),
                'path' => 'counter',
                'type' => 'string',
            ],
            [
                'key' => __('Colour'),
                'path' => 'colour',
            ],
            [
                'key' => __('Created'),
                'path' => 'created',
            ],
        ],
        'children' => []
    ]
);
