<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $warninglist,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'info-circle',

                // Content
                'left' => [
                    'Warninglists/View/warninglists_general',
                    'Warninglists/View/warninglists_values',
                ],
                'right' => [
                    'Warninglists/View/warninglists_actions',
                ]
            ],
        ]
    ]);
?>

