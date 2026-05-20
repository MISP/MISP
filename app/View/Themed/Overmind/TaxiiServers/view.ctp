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
                    'TaxiiServers/View/taxiiServers_general',
                ],
                'right' => [
                    'TaxiiServers/View/taxiiServers_actions',
                ]
            ],
            [
                'id' => 'collections',
                'title' => __('Collections'),
                'icon' => 'folder',
                //'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/taxii_servers/collectionsIndex/%s', h($data['TaxiiServer']['id']))
                    ]
                ],
            ],
            [
                'id' => 'objects',
                'title' => __('Objects in selected Collection'),
                'icon' => 'cube',
                //'count' => $tag_count ?? 0,

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/taxii_servers/objectsIndex/%s', h($data['TaxiiServer']['id']))
                    ]
                ],
            ]
        ]
    ]);
?>

