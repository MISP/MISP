<?php
$decodedArgs = json_decode($passedArgs, true) ?: [];
$searchall = $decodedArgs['searchall'] ?? '';

// Only used when rendered as a standalone page (ignored in the ajax fragment).
$this->set('headerTitle', __('Galaxy clusters'));

// Default clusters have no meaningful "published" state.
foreach ($list as $i => $cluster) {
    if (!empty($cluster['GalaxyCluster']['default'])) {
        $list[$i]['GalaxyCluster']['published'] = null;
    }
}

// Pagination links must carry the current context / search so in-tab reloads land on the right slice.
$paginatorUrl = [$galaxy_id];
if (!empty($context) && $context !== 'all') {
    $paginatorUrl['context'] = $context;
}
if (!empty($searchall)) {
    $paginatorUrl['searchall'] = $searchall;
}
$paginatorUrl += $metaParams ?? [];
$this->Paginator->options(['url' => $paginatorUrl]);

$clustersUrl = $baseurl . '/galaxy_clusters/index/' . h($galaxy_id);
$myClustersUrl = $clustersUrl . '/context:' . ($context === 'orgc' ? 'all' : 'orgc');
foreach (array_diff_key($paginatorUrl, [0 => true, 'context' => true]) as $name => $value) {
    $myClustersUrl .= '/' . $name . ':' . rawurlencode($value);
}

$metaPickers = [];
foreach (($metaFacets ?? []) as $key => $facet) {
    $metaPickers[] = [
        'type' => 'dropdown',
        'label' => $facet['label'],
        'name' => GalaxyElementFacets::PARAM_PREFIX . $key,
        'options' => array_combine($facet['values'], $facet['values']),
        'separator' => GalaxyElementFacets::SEPARATOR,
        'exclude' => true,
    ];
}

$showOwnerOrg = $isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'));
$showCreatorOrg = $isSiteAdmin || Configure::read('MISP.showorg') || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'));

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'GalaxyCluster.id',
        'enable_path' => 'GalaxyCluster.enabled',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'GalaxyCluster.id',
        'data_path' => 'GalaxyCluster.id',
        'element' => 'id',
        'url' => $baseurl . '/galaxy_clusters/view/%id%',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'GalaxyCluster.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Name'),
        'data_path' => 'GalaxyCluster',
        'element' => 'cluster_value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Published'),
        'data_path' => 'GalaxyCluster.published',
        'element' => 'published',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Synonyms'),
        'data_path' => 'GalaxyCluster.synonyms',
        'element' => 'synonyms',
        'card_section' => 'tag',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Owner Org'),
        'data_path' => 'Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card'],
        'requirement' => $showOwnerOrg,
    ],
    [
        'name' => __('Creator Org'),
        'data_path' => 'Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'requirement' => $showCreatorOrg,
    ],
    [
        'name' => __('Default'),
        'data_path' => 'GalaxyCluster.default',
        'element' => 'default',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        // How many times this cluster's tag is used on events and attributes.
        'name' => __('#Relations'),
        'data_path' => 'GalaxyCluster',
        'element' => 'cluster_relations',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'GalaxyCluster.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $baseurl . '/galaxy_clusters/view/%id%',
            ],
            [
                'type' => 'navigate',
                'label' => __('View correlation graph'),
                'icon' => 'share-nodes',
                'url' => $baseurl . '/galaxies/viewGraph/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/galaxy_clusters/edit/%id%',
                'requirement' => function ($row) use ($me) {
                    return empty($row['GalaxyCluster']['default'])
                        && (!empty($me['Role']['perm_site_admin'])
                            || ($me['org_id'] == $row['GalaxyCluster']['org_id'] && !empty($me['Role']['perm_galaxy_editor'])));
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Fork'),
                'icon' => 'code-branch',
                'url' => $baseurl . '/galaxy_clusters/add/%galaxy_id%/forkUuid:%uuid%',
                'url_params_data_paths' => [
                    'galaxy_id' => 'GalaxyCluster.galaxy_id',
                    'uuid' => 'GalaxyCluster.uuid',
                ],
                'requirement' => function ($row) use ($me) {
                    return !empty($me['Role']['perm_galaxy_editor']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Contribute to misp-galaxy'),
                'icon' => 'handshake',
                'url' => $baseurl . '/galaxy_clusters/export_for_misp_galaxy/%id%',
                'requirement' => function ($row) {
                    return empty($row['GalaxyCluster']['default']);
                },
            ],
            [
                'type' => 'divider',
            ],
            [
                'type' => 'modal',
                'label' => __('Publish'),
                'icon' => 'upload',
                'url' => $baseurl . '/galaxy_clusters/publish/%id%',
                'size' => 'md',
                'requirement' => function ($row) use ($me) {
                    return empty($row['GalaxyCluster']['published'])
                        && (!empty($me['Role']['perm_site_admin'])
                            || ($me['org_id'] == $row['GalaxyCluster']['orgc_id'] && !empty($me['Role']['perm_galaxy_editor']) && !empty($me['Role']['perm_publish'])));
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Restore'),
                'icon' => 'trash-arrow-up text-success',
                'url' => $baseurl . '/galaxy_clusters/restore/%id%',
                'size' => 'md',
                'requirement' => function ($row) use ($me) {
                    return !empty($row['GalaxyCluster']['deleted'])
                        && (!empty($me['Role']['perm_site_admin']) || $me['org_id'] == $row['GalaxyCluster']['orgc_id']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/galaxy_clusters/delete/%id%',
                'size' => 'md',
                'requirement' => function ($row) use ($me) {
                    return !empty($me['Role']['perm_site_admin'])
                        || ($me['org_id'] == $row['GalaxyCluster']['org_id'] && !empty($me['Role']['perm_galaxy_editor']));
                },
            ],
        ],
    ],
];
?>

<?php
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $list,
            'cards_per_row' => 4,
            'filter_bar' => [
                'base_url' => $clustersUrl,
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search value, description, synonym or UUID'),
                        'name' => 'searchall',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'button',
                        'label' => __('My Clusters'),
                        'icon' => 'fas fa-user',
                        'class' => 'btn ' . ($context === 'orgc' ? 'btn-primary' : 'btn-outline-primary'),
                        'url' => $myClustersUrl,
                    ],
                    [
                        'type' => 'button',
                        'label' => __('Deleted') . (!empty($deletedCount) ? ' (' . (int)$deletedCount . ')' : ''),
                        'icon' => 'fas fa-trash',
                        'class' => 'btn ' . ($context === 'deleted' ? 'btn-danger' : 'btn-outline-danger'),
                        'url' => $baseurl . '/galaxy_clusters/index/' . $galaxy_id . '/context:' . ($context === 'deleted' ? 'all' : 'deleted'),
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => array_merge([
                            [
                                'type' => 'dropdown',
                                'label' => __('Context'),
                                'name' => 'context',
                                'col' => 4,
                                'options' => [
                                    '' => '',
                                    'default' => __('Default'),
                                    'custom' => __('Custom'),
                                    'orgc' => __('Created by my organisation'),
                                    'org' => __('Owned by my organisation'),
                                    'deleted' => __('Deleted'),
                                ],
                            ],
                        ], $metaPickers),
                    ],
                ],
                // Mass delete (soft/hard) via deleteSelection. delete_url is absolute because item_url carries the galaxy id.
                'delete' => ($isSiteAdmin || !empty($me['Role']['perm_galaxy_editor'])) ? '/deleteSelection' : null,
                'delete_url' => '/galaxy_clusters/deleteSelection',
            ],
            'fields' => $fields,
            'primary_id_path' => 'GalaxyCluster.id',
            'row_dblclick_url' => $baseurl . '/galaxy_clusters/view/%id%',
        ],
    ],
    'item_url' => '/galaxy_clusters/index/' . $galaxy_id,
]);
?>
