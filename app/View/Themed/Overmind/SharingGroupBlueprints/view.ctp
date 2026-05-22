<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $data,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'info-circle',

                // Content
                'left' => [
                    'SharingGroupBlueprints/View/sharingGroupBlueprints_general',
                ],
                'right' => [
                    'SharingGroupBlueprints/View/sharingGroupBlueprints_actions',
                ]
            ],
            [
                'id' => 'organisations',
                'title' => __('Organisations'),
                'icon' => 'building-user',
                //'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/SharingGroupBlueprints/viewOrgs/%s', h($data['SharingGroupBlueprint']['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

