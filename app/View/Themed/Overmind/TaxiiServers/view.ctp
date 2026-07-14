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
                    'TaxiiServers/View/taxiiServers_general',
                ],
                'right' => [
                    'TaxiiServers/View/taxiiServers_actions',
                ]
            ],
            [
                'id' => 'collections',
                'title' => __('Collections'),
                'icon' => 'fas fa-folder',

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
                'icon' => 'fas fa-cube',

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('/taxii_servers/objectsIndex/%s/%s', h($data['TaxiiServer']['id']), h($data['TaxiiServer']['collection']))
                    ]
                ],
            ]
        ]
    ]);
?>

