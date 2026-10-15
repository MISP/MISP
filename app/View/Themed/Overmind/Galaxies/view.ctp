<?php
$this->set('headerIdentity', $galaxy['Galaxy']);
$data = $galaxy['Galaxy'];
$railCards = $railCards ?? [];

$this->set('headerTitle', $data['name']);
$palette = $this->GalaxyColour->palette($data['name'] ?? '');
$this->set('headerTitleHtml', sprintf(
    '<span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 align-self-center rounded-3 shadow-sm me-3"'
    . ' style="width:1.4em;height:1.4em;background:%s;color:%s;"><i class="%s" style="font-size:.6em;"></i></span>'
    . '<span class="d-flex flex-column justify-content-center min-w-0"><span>%s</span>%s</span>',
    h($palette['tintBg']),
    h($palette['tintIcon']),
    h(!empty($data['icon']) ? $this->FontAwesome->getClass($data['icon']) : 'fas fa-shapes'),
    h($data['name'] ?? ''),
    empty($data['namespace']) ? '' : sprintf(
        '<span class="fw-normal text-body-secondary mt-1" style="font-size:.4em;" title="%s">'
        . '<i class="fas fa-folder-tree me-1 opacity-50"></i>%s</span>',
        h(__('Namespace')),
        h($data['namespace'])
    )
));

if (!empty($isMatrixGalaxy)) {
    echo $this->element('genericElements/assetLoader', [
        'css' => ['misp-matrix'],
        'js' => ['misp-matrix'],
    ]);
}

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $data['Orgc'] ?? [],
        'org' => $data['Org'] ?? [],
        'distribution' => $data['distribution'] ?? null,
    ],
    'tabs' => array_values(array_filter([
        [
            'id' => 'general',
            'title' => __('General'),
            'icon' => 'fas fa-info-circle',
            'left' => [
                'Galaxies/View/galaxies_general',
                'Galaxies/View/galaxies_clusters_card',
            ],
            'right' => array_merge([
                'Galaxies/View/galaxies_actions',
                'Galaxies/View/galaxies_analyst_data',
            ], $this->RailCard->rail($railCards, [
                'galaxy-composition', 'galaxy-usage',
            ], 'general')),
        ],
        [
            'id' => 'clusters',
            'title' => __('Clusters'),
            'icon' => 'fas fa-diagram-project',
            'count' => $clusterCount ?? 0,
            'left' => [
                [
                    'ajax' => $baseurl . '/galaxy_clusters/index/' . h($data['id']),
                ],
            ],
            'right' => $this->RailCard->rail($railCards, ['galaxy-composition'], 'clusters'),
        ],
        empty($isMatrixGalaxy) ? null : [
            'id' => 'matrix',
            'title' => __('Matrix'),
            'icon' => 'fas fa-table-cells',
            'left' => [
                [
                    'ajax' => $baseurl . '/galaxies/viewMatrix/' . h($data['id']),
                ],
            ],
        ],
    ])),
]);
