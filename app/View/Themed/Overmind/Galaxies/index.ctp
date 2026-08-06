<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];

if ($isSiteAdmin) {
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Force Update Galaxies'),
        'icon' => 'bolt',
        'url' => $baseurl . '/galaxies/update/force:1',
        'confirm' => __('Are you sure you want to drop and reimport all galaxies from the submodule?')
    ];
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Wipe Default Clusters'),
        'icon' => 'trash',
        'url' => $baseurl . '/galaxies/wipe_default',
        'confirm' => __('Are you sure you want to drop all default galaxy clusters?')
    ];
    $headerActions[] = [
        'type' => 'action',
        'label' => __('Update Galaxies'),
        'icon' => 'sync',
        'url' => $baseurl . '/galaxies/update',
        'confirm' => __('Are you sure you want to reimport all galaxies from the submodule?')
    ];
}

if ($this->Acl->canAccess('galaxies', 'import')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Import Galaxy Clusters'),
        'icon' => 'upload',
        'url' => $baseurl . '/galaxies/import'
    ];
}
if ($this->Acl->canAccess('galaxies', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Custom Galaxy'),
        'icon' => 'plus',
        'url' => $baseurl . '/galaxies/add'
    ];
}

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


/**
 * ==============================================================
 * Admin notices about unknown clusters (informational only)
 * ==============================================================
 */
if ($isSiteAdmin && !empty($unknownClustersDetails)) {
    $notices = [];
    if (!empty($unknownClustersDetails['unknownCustomClusters'])) {
        $content = sprintf(__('Your instance has detected <strong>%s</strong> <strong>custom cluster(s)</strong> that it doesn\'t recognize. This may indicate one of two things: either these clusters haven\'t been properly synchronized, or you weren\'t authorized to view them during the synchronization process. In most cases, you can safely ignore this message. However, if you believe you should have access to these clusters, please check your synchronization settings and ask the instances sending data to you to review theirs as well. Sample(s):'), h($unknownClustersDetails['unknownCustomClusters']));
        $content .= '<ul class="mb-0 mt-2"><li>' . implode('</li><li>', array_map('h', $unknownClustersDetails['unknownCustomClustersSamples'])) . '</li></ul>';
        $notices[] = $content;
    }
    if (!empty($unknownClustersDetails['unknownDefaultClusters'])) {
        $content = sprintf(__('Your instance has detected <strong>%s</strong> <strong>default cluster(s)</strong> that it doesn\'t recognize, which may mean your galaxies are outdated. To fix this, update to the latest version from the misp-galaxy repository and load the JSON files into your database by clicking the "Update Galaxies" button. Sample(s):'), h($unknownClustersDetails['unknownDefaultClusters']));
        $content .= '<ul class="mb-0 mt-2"><li>' . implode('</li><li>', array_map('h', $unknownClustersDetails['unknownDefaultClustersSamples'])) . '</li></ul>';
        $notices[] = $content;
    }
    if (!empty($notices)) {
        echo '<div class="container-fluid">';
        echo '<div class="accordion mb-3" id="accordionClusterInfo">';
        echo '<div class="accordion-item border-info">';
        echo '<h2 class="accordion-header" id="clusterInfoHeading">';
        echo '<button class="accordion-button collapsed bg-info-subtle text-info-emphasis fw-semibold" type="button" data-bs-toggle="collapse" data-bs-target="#clusterInfoCollapse" aria-expanded="false" aria-controls="clusterInfoCollapse">';
        echo '<i class="fas fa-circle-info me-2"></i>' . __('Show information about your clusters');
        echo '</button></h2>';
        echo '<div id="clusterInfoCollapse" class="accordion-collapse collapse" aria-labelledby="clusterInfoHeading" data-bs-parent="#accordionClusterInfo">';
        echo '<div class="accordion-body">';
        echo '<p class="text-muted">' . __('This information is purely informational and is typically part of the normal operation of the system.') . '</p>';
        foreach ($notices as $notice) {
            echo '<div class="alert alert-info mb-2">' . $notice . '</div>';
        }
        echo '</div></div></div></div></div>';
    }
}


/**
 * ==============================================================
 * Definition of fields displayed in the scaffold
 * ==============================================================
 */
$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Galaxy.id',
        'enable_path' => 'Galaxy.enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Galaxy.id',
        'data_path' => 'Galaxy.id',
        'element' => 'id',
        'url' => $baseurl . '/galaxies/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Name'),
        'sort' => 'name',
        'data_path' => 'Galaxy.name',
        'element' => 'galaxy_name',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Namespace'),
        'sort' => 'Galaxy.namespace',
        'data_path' => 'Galaxy.namespace',
        'element' => 'namespace',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'Galaxy.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['table','card']
    ],
    [
        'name' => __('Version'),
        'data_path' => 'Galaxy.version',
        'element' => 'version',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'enabled',
        'data_path' => 'Galaxy.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Local Only'),
        'sort' => 'local_only',
        'data_path' => 'Galaxy.local_only',
        'element' => 'local',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Galaxy.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/galaxies/view/%id%'
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/galaxies/edit/%id%',
                'requirement' => function ($row) use ($isSiteAdmin, $me) {
                    return !$row['Galaxy']['default'] && ($isSiteAdmin || ($row['Galaxy']['org_id'] === $me['org_id'] && $me['Role']['perm_galaxy_editor']));
                }
            ],
            [
                'type' => 'divider',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'modal',
                'label' => __('Enable'),
                'icon' => 'play text-success',
                'url' => $baseurl . '/galaxies/enable/%id%',
                'size' => 'sm',
                'requirement' => function ($row) use ($isSiteAdmin) {
                    return $isSiteAdmin && empty($row['Galaxy']['enabled']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Disable'),
                'icon' => 'stop text-danger',
                'url' => $baseurl . '/galaxies/disable/%id%',
                'size' => 'sm',
                'requirement' => function ($row) use ($isSiteAdmin) {
                    return $isSiteAdmin && !empty($row['Galaxy']['enabled']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/galaxies/deleteSelection/%id%',
                'requirement' => $isSiteAdmin
            ]
        ]
    ],
];


/**
 * ==============================================================
 * Call the generic scaffold
 * ==============================================================
 */
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $galaxyList,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by galaxy name'),
                        'name'        => 'value',
                        'mode'        => 'legacy',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Enabled'),
                                'name' => 'enabled',
                                'options' => [
                                    '' => __('All'),
                                    '1' => __('Enabled'),
                                    '0' => __('Disabled'),
                                ]
                            ],
                        ]
                    ],
                ],
                'enable' => 1,
                'delete' => '/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'Galaxy.id',
            'row_dblclick_url' => $baseurl . '/galaxies/view/%id%',
        ]
    ],
    'item_url' => '/galaxies'
]);
