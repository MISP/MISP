<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $community,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'fas fa-info-circle',

                // Content
                'left' => [
                    'Communities/View/communities_general',
                ],
                'right' => [
                    'Communities/View/communities_actions',
                ]
            ]
        ]
    ]);
?>

