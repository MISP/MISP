<?php
    $headerTitle = __('') . ($data['Cerebrate']['name'] ?? '');
    $headerDescription = '';
    $headerActions = [];


    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);


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
                'description' => 'Preview of the organisations known to the remote Cerebrate instance.',
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
                'title' => __('Sharing Groups'),__('.'),
                'icon' => 'fas fa-share-alt',
                'description' => 'Preview of the sharing groups known to the remote Cerebrate instance',
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

