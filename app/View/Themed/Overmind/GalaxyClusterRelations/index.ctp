<?php
$this->set('headerTitle', __('Galaxy Cluster Relationships'));
$this->set('headerDescription', __('All relationships between galaxy clusters.'));
$headerActions = [];
if ($this->Acl->canAccess('galaxy_cluster_relations', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add relationship'),
        'icon' => 'plus',
        'url' => $baseurl . '/galaxy_cluster_relations/add'
    ];
}
$this->set('headerActions', $headerActions);

$showOwnerOrg = $isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'));
$showCreatorOrg = $isSiteAdmin || Configure::read('MISP.showorg') || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'));

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'GalaxyClusterRelation.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'GalaxyClusterRelation.id',
        'data_path' => 'GalaxyClusterRelation.id',
        'element' => 'id',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Source'),
        'sort' => 'SourceCluster.tag_name',
        'data_path' => 'SourceCluster',
        'element' => 'cluster_value',
        'url' => $baseurl . '/galaxy_clusters/view/%id%',
        'hide_description' => true,
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Relationship'),
        'sort' => 'type',
        'data_path' => 'GalaxyClusterRelation.referenced_galaxy_cluster_type',
        'element' => 'relationship_type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Target'),
        'sort' => 'TargetCluster.tag_name',
        'data_path' => 'TargetCluster',
        'element' => 'cluster_value',
        'url' => $baseurl . '/galaxy_clusters/view/%id%',
        'hide_description' => true,
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'GalaxyClusterRelationTag',
        'element' => 'custom',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'function' => function ($row) {
            $relTags = $row['GalaxyClusterRelationTag'] ?? [];
            if (empty($relTags)) {
                return '<span class="text-muted">-</span>';
            }
            $out = '<div class="d-flex flex-wrap align-items-center">';
            foreach ($relTags as $relTag) {
                $tag = $relTag['Tag'] ?? null;
                if (empty($tag['name'])) {
                    continue;
                }
                if (empty($tag['colour'])) {
                    $tag['colour'] = '#' . substr(md5($tag['name']), 0, 6);
                }
                $out .= $this->element('genericElementsBS5/Badges/tag', [
                    'tag' => $tag,
                    'local' => !empty($tag['local']),
                    'hiddenClass' => '',
                ]);
            }
            return $out . '</div>';
        },
    ],
    [
        'name' => __('Default'),
        'sort' => 'GalaxyClusterRelation.default',
        'data_path' => 'GalaxyClusterRelation.default',
        'element' => 'default',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Owner Org'),
        'data_path' => 'SourceCluster.Org',
        'element' => 'organisation',
        // Default galaxy data is owned by org 0 — show MISP, like legacy.
        'default_org' => 'MISP',
        'card_section' => 'meta',
        'display_in' => ['card'],
        'requirement' => $showOwnerOrg,
    ],
    [
        'name' => __('Creator Org'),
        'data_path' => 'SourceCluster.Orgc',
        'element' => 'organisation',
        'default_org' => 'MISP',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'requirement' => $showCreatorOrg,
    ],
    [
        'name' => __('Distribution'),
        'sort' => 'distribution',
        'data_path' => 'GalaxyClusterRelation.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'GalaxyClusterRelation.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/galaxy_cluster_relations/edit/%id%',
                'requirement' => function ($row) use ($me) {
                    return empty($row['GalaxyClusterRelation']['default'])
                        && (!empty($me['Role']['perm_site_admin'])
                            || ($me['org_id'] == ($row['SourceCluster']['org_id'] ?? null) && !empty($me['Role']['perm_galaxy_editor'])));
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/galaxy_cluster_relations/delete/%id%',
                'requirement' => function ($row) use ($me) {
                    return !empty($me['Role']['perm_site_admin'])
                        || ($me['org_id'] == ($row['SourceCluster']['org_id'] ?? null) && !empty($me['Role']['perm_galaxy_editor']));
                },
            ],
        ],
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by cluster, tag or relationship type'),
                        'name' => 'searchall',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'dropdown',
                        'label' => __('Context'),
                        'name' => 'context',
                        'options' => [
                            '' => __(''),
                            'default' => __('Default'),
                            'custom' => __('Custom'),
                        ],
                    ],
                ],
            ],
            'fields' => $fields,
            'primary_id_path' => 'GalaxyClusterRelation.id',
        ],
    ],
    'item_url' => '/galaxy_cluster_relations',
]);
