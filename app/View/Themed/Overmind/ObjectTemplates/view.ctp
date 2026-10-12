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
                        'ajax' => sprintf('%s/objectTemplateElements/viewElements/%s/all', $baseurl, h($data['ObjectTemplate']['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

