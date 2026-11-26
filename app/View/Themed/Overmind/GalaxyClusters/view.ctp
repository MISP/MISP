<?php
$this->set('headerIdentity', $cluster['GalaxyCluster']);
$data = $cluster['GalaxyCluster'];

$this->set('headerTitle', $data['value']);
$galaxyName = $data['Galaxy']['name'] ?? $data['Galaxy']['type'] ?? '';
$palette = $this->GalaxyColour->palette($galaxyName);
$this->set('headerTitleHtml', sprintf(
    '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 align-self-center rounded-3 shadow-sm me-3"'
    . ' style="width:1.4em;height:1.4em;background:%s;color:%s;"><i class="%s" style="font-size:.6em;"></i></span>'
    . '<span class="d-flex flex-column justify-content-center min-w-0"><span>%s</span>'
    . '<a class="fw-normal text-body-secondary text-decoration-none mt-1" style="font-size:.4em;" href="%s" title="%s">'
    . '<i class="fas fa-shapes me-1 opacity-50"></i>%s</a></span>',
    h($palette['tintBg']),
    h($palette['tintIcon']),
    h(!empty($data['Galaxy']['icon']) ? $this->FontAwesome->getClass($data['Galaxy']['icon']) : 'fas fa-diagram-project'),
    h($data['value'] ?? ''),
    h($baseurl . '/galaxies/view/' . ($data['Galaxy']['id'] ?? $data['galaxy_id'] ?? '')),
    h(__('Galaxy')),
    h($galaxyName)
));

$elementCount = isset($data['GalaxyElement']) ? count($data['GalaxyElement']) : 0;

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $data['Orgc'] ?? [],
        'org' => $data['Org'] ?? [],
        'distribution' => $data['distribution'] ?? null,
        'sharingGroup' => $data['SharingGroup'] ?? [],
    ],
    'tabs' => [
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'GalaxyClusters/View/galaxy_clusters_general',
                'GalaxyClusters/View/galaxy_clusters_elements_card',
            ],
            'right' => [
                'GalaxyClusters/View/galaxy_clusters_actions',
                'GalaxyClusters/View/galaxy_clusters_analyst_data',
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
