<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $sg,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'fas fa-info-circle',

                // Content
                'left' => [
                    'SharingGroups/View/sharingGroups_general',
                ],
                'right' => [
                    'SharingGroups/View/sharingGroups_actions',
                ]
            ]
        ]
    ]);
?>

