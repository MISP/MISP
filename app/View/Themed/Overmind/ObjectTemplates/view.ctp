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
                    'ObjectTemplates/View/objectTemplate_general',
                ],
                'right' => [
                    'ObjectTemplates/View/objectTemplate_actions',
                ]
            ],
            [
                'id' => 'elements',
                'title' => __('Elements'),
                'icon' => 'fas fa-cube',

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/objectTemplateElements/viewElements/%s/all', h($data['ObjectTemplate']['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

