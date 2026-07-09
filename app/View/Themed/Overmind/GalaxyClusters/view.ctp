<?php
$data = $cluster['GalaxyCluster'];

$this->set('headerTitle', $data['value']);

$elementCount = isset($data['GalaxyElement']) ? count($data['GalaxyElement']) : 0;

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'GalaxyClusters/View/galaxy_clusters_general',
            ],
            'right' => [
                'GalaxyClusters/View/galaxy_clusters_actions',
            ],
        ],
        [
            'id' => 'elements',
            'title' => __('Elements'),
            'icon' => 'fas fa-list-ul',
            'count' => $elementCount,
            'left' => [
                [
                    'ajax' => $baseurl . '/galaxy_elements/index/' . h($data['id']),
                ],
            ],
        ],
        [
            'id' => 'relations',
            'title' => __('Relations'),
            'icon' => 'fas fa-diagram-project',
            'left' => [
                [
                    'ajax' => $baseurl . '/galaxy_clusters/viewRelations/' . h($data['id']),
                ],
            ],
        ],
    ],
]);
