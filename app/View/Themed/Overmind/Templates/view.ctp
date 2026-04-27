<?php
    echo $this->element('genericElementsBS5/Layout/view_layout',
    [
        'data' => $template,
        'tabs' => [
            [
                'id' => 'general',
                'title' => __('General'),
                'icon' => 'info-circle',

                // Content
                'left' => [
                    'Templates/View/templates_general',
                ],
                'right' => [
                    'Templates/View/templates_actions',
                ]
            ],
            [
                'id' => 'elements',
                'title' => __('Elements'),
                'icon' => 'file-code',
                'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/template_elements/index/%s', h($template['Template']['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

