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
                    'Collections/View/collection_general',
                ],
                'right' => [
                    'Collections/View/collection_actions',
                ]
            ],
            [
                'id' => 'elements',
                'title' => __('Elements'),
                'icon' => 'file',

                // Content
                'left' => [
                    'Collections/View/collection_elements',
                ],
            ]
        ]
    ]);
?>

