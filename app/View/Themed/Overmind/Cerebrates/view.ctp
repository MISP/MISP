<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $data,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'fas fa-info-circle',

                // Content
                'left' => [
                    'Cerebrates/View/cerebrates_general',
                ],
                'right' => [
                    'Cerebrates/View/cerebrates_actions',
                ]
            ],
            [
                'id' => 'organisations',
                'title' => __('Organisations'),
                'icon' => 'fas fa-building-user',
                //'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/cerebrates/preview_orgs/%s', h($data['Cerebrate']['id']))
                    ]
                ],
            ],
            [
                'id' => 'sgs',
                'title' => __('Sharing Groups'),
                'icon' => 'fas fa-share-alt',
                //'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/cerebrates/preview_sharing_groups/%s', h($data['Cerebrate']['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

