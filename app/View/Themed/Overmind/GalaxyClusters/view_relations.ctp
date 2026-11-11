<?php
$canEdit = ($me['org_id'] == $cluster['GalaxyCluster']['org_id']) || !empty($me['Role']['perm_site_admin']);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('Direction'),
        'data_path' => 'isInbound',
        'element' => 'custom',
        'function' => function ($row) {
            $inbound = !empty($row['isInbound']);
            return $inbound
                ? '<span class="badge bg-info-subtle text-info-emphasis"><i class="fas fa-arrow-left-long me-1"></i>' . __('Inbound') . '</span>'
                : '<span class="badge bg-primary-subtle text-primary-emphasis"><i class="fas fa-arrow-right-long me-1"></i>' . __('Outbound') . '</span>';
        },
    ],
    [
        'name' => __('Relationship'),
        'data_path' => 'referenced_galaxy_cluster_type',
        'element' => 'relationship_type',
    ],
    [
        'name' => __('Target (galaxy :: cluster)'),
        'data_path' => 'GalaxyCluster',
        'element' => 'custom',
        'function' => function ($row) use ($baseurl) {
            $t = $row['GalaxyCluster'] ?? null;
            if (empty($t) || empty($t['id'])) {
                return '<span class="text-muted">-</span>';
            }
            $galaxyName = $t['Galaxy']['name'] ?? ($t['Galaxy']['type'] ?? '');
            $label = ($galaxyName !== '' ? h($galaxyName) . ' :: ' : '') . h($t['value'] ?? '');
            return '<a href="' . $baseurl . '/galaxy_clusters/view/' . h($t['id']) . '" class="text-decoration-none fw-semibold">' . $label . '</a>';
        },
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'Tag',
        'element' => 'custom',
        'function' => function ($row) {
            $tags = $row['Tag'] ?? [];
            if (empty($tags)) {
                return '<span class="text-muted">-</span>';
            }
            // Normalise a single tag to a list.
            if (isset($tags['name'])) {
                $tags = [$tags];
            }
            $out = '<div class="d-flex flex-wrap align-items-center">';
            foreach ($tags as $tag) {
                if (empty($tag['name'])) {
                    continue;
                }
                // Fall back to a deterministic colour if none is provided.
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
        'name' => __('Distribution'),
        'data_path' => 'distribution',
        'element' => 'distribution',
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'id',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/galaxy_cluster_relations/edit/%id%',
                // Default relations cannot be edited (the controller rejects them).
                'requirement' => function ($row) use ($canEdit) {
                    return $canEdit && empty($row['default']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/galaxy_cluster_relations/delete/%id%',
                'requirement' => $canEdit,
            ],
        ],
    ],
];

if (empty($relations)) {
    echo '<div class="text-center text-muted py-5">'
        . '<i class="fas fa-diagram-project fa-2x mb-2 opacity-50"></i><br>'
        . __('This cluster has no relationships.')
        . '</div>';
} else {
    echo $this->element('genericElementsBS5/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $relations,
                'skip_pagination' => true,
                'fields' => $fields,
                'primary_id_path' => 'id',
            ],
        ],
        'item_url' => '/galaxy_clusters/viewRelations/' . h($cluster['GalaxyCluster']['id']),
    ]);
}
