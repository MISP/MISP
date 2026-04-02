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
                    'Noticelists/View/noticelists_general',
                    'Noticelists/View/noticelists_values',
                ],
            ],
        ]
    ]);
?>

