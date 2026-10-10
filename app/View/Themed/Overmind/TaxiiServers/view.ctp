<?php
    $headerTitle = __('') . ($data['TaxiiServer']['name'] ?? '');
    $headerDescription = '';
    $headerActions = [];


    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

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
                'description' => __('The collections advertised by the remote TAXII server.'),

                // Content
                'left' => [
                    [
                        'ajax' => sprintf('%s/taxii_servers/collectionsIndex/%s', $baseurl, h($data['TaxiiServer']['id']))
                    ]
                ],
            ],
            [
                'id' => 'objects',
                'title' => __('Objects in selected Collection'),
                'icon' => 'fas fa-cube',
                'description' => __('STIX objects retrieved from the remote TAXII collection.'),

                // Content
                'left' => [
                    [
                        'ajax' => rtrim(sprintf('/taxii_servers/objectsIndex/%s/%s', h($data['TaxiiServer']['id']), h($data['TaxiiServer']['collection'] ?? '')), '/')
                    ]
                ],
            ]
        ]
    ]);
?>

