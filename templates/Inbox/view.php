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
                'key' => 'created',
                'path' => 'created',
            ],
            [
                'key' => 'scope',
                'path' => 'scope',
            ],
            [
                'key' => 'action',
                'path' => 'action',
            ],
            [
                'key' => 'title',
                'path' => 'title',
            ],
            [
                'key' => 'origin',
                'path' => 'origin',
            ],
            [
                'key' => 'user_id',
                'path' => 'user_id',
            ],
            [
                'key' => 'message',
                'path' => 'message',
            ],
            [
                'key' => 'comment',
                'path' => 'comment',
            ],
            [
                'key' => 'data',
                'path' => 'data',
                'type' => 'json'
            ],
        ],
        'children' => []
    ]
);
