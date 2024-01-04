<?php
echo $this->element(
    'genericElements/SingleViews/single_view',
    [
        'title' => __('Note view'),
        'data' => $data,
        'fields' => [
            [
                'key' => __('ID'),
                'path' => $modelSelection . '.id'
            ],
            [
                'key' => __('UUID'),
                'path' => $modelSelection . '.uuid'
            ],
            [
                'key' => __('Target Object'),
                'type' => 'custom',
                'function' => function (array $row) use ($baseurl) {
                    $path = Inflector::pluralize(strtolower($row['Note']['object_type']));
                    return sprintf(
                        '<span class="bold">%s</span>: <a href="%s/%s/view/%s">%s</a>',
                        h($row['Note']['object_type']),
                        h($baseurl),
                        h($path),
                        h($row['Note']['object_uuid']),
                        h($row['Note']['object_uuid'])
                    );

                }
            ],
            [
                'key' => __('Creator org'),
                'path' => $modelSelection . '.orgc_uuid',
                'pathName' => $modelSelection . '.orgc_uuid',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Owner org'),
                'path' => $modelSelection . '.org_uuid',
                'pathName' => $modelSelection . '.org_uuid',
                'type' => 'model',
                'model' => 'organisations'
            ],
            [
                'key' => __('Created'),
                'path' => $modelSelection . '.created'
            ],
            [
                'key' => __('Modified'),
                'path' => $modelSelection . '.modified'
            ],
            [
                'key' => __('Distribution'),
                'path' => $modelSelection . '.distribution',
                'event_id_path' => $modelSelection . '.id',
                'disable_distribution_graph' => true,
                'sg_path' => $modelSelection . '.sharing_group_id',
                'type' => 'distribution'
            ],
            [
                'key' => __('Language'),
                'path' => $modelSelection . '.language'
            ],
            [
                'key' => __('Note'),
                'path' => $modelSelection . '.note'
            ]
        ]
    ]
);
