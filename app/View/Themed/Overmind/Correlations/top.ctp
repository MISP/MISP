<?php

$onDemandEngine = !empty($onDemandEngine);
$canExclude = $this->Acl->canAccess('correlation_exclusions', 'add');

// Header section
$this->set('headerTitle', __('Top correlations'));
$this->set('headerDescription', __('The values with the most correlation entries.'));

$headerActions = [
    [
        'type' => 'action',
        'label' => __('Regenerate cache'),
        'icon' => 'sync',
        'url' => $baseurl . '/correlations/generateTopCorrelations',
    ],
];
$this->set('headerActions', $headerActions);

// Cache age is only meaningful for the cached (Redis) engine.
if (!$onDemandEngine) {
    $this->set('headerStats', [
        [
            'label' => __('Cache age'),
            'value' => sprintf('%s%s', $age, $age_unit),
            'subtitle' => __('Since last regeneration'),
            'subtitleIcon' => 'clock',
            'icon' => 'database',
            'color' => 'info',
        ],
    ]);
}

$fields = [];

$fields[] = [
    'element' => 'checkbox',
    'data_path' => 'Correlation.id',
    'card_section' => 'selector',
];


$fields[] =
    [
        'name' => __('Value'),
        'data_path' => 'Correlation.value',
        'element' => 'custom',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) use ($baseurl) {
            $value = Hash::get($row, 'Correlation.value');
            if ($value === null || $value === '') {
                return '<span class="text-muted">&mdash;</span>';
            }
            return sprintf(
                '<a href="%s/attributes/search/value:%s" class="text-decoration-none font-monospace" title="%s">%s</a>',
                $baseurl,
                urlencode($value),
                h(__('Search for attributes with this value')),
                h($value)
            );
        },
    ];
$fields[] =    [
        'name' => __('Excluded'),
        'data_path' => 'Correlation.excluded',
        'element' => 'custom',
        'class' => 'short',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) {
            $excluded = !empty(Hash::get($row, 'Correlation.excluded'));
            if ($excluded) {
                return '<span class="badge text-bg-danger">'
                    . '<i class="fas fa-ban me-1"></i>' . h(__('Excluded')) . '</span>';
            }
            return '<span class="text-muted">&mdash;</span>';
        },
    ];
$fields[] =  [
    'name' => __('Correlation count'),
    'data_path' => 'Correlation.count',
    'element' => 'count',
    'card_section' => 'top',
    'display_in' => ['table', 'card']
];
$fields[] =  [
    'name' => __('Actions'),
    'data_path' => 'Correlation.value',
    'element' => 'custom',
    'card_section' => 'extra',
    'display_in' => ['table', 'card'],
    'function' => function (array $row) use ($baseurl, $canExclude) {
        $value = Hash::get($row, 'Correlation.value');
        $excluded = !empty(Hash::get($row, 'Correlation.excluded'));
        if (!$canExclude || $excluded || $value === null || $value === '') {
            return '';
        }
        $url = sprintf('%s/correlation_exclusions/add/value:%s', $baseurl, urlencode($value));
        return sprintf(
            '<button type="button" class="btn btn-sm btn-outline-danger" '
                . 'title="%s" onclick="openModal(\'%s\')">'
                . '<i class="fas fa-ban me-1"></i>%s</button>',
            h(__('Add exclusion entry for value')),
            h($url),
            h(__('Exclude'))
        );
    },
];


echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'skip_pagination' => true,
            'filter_bar' => [
                'children' => [],
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/correlations'
]);
