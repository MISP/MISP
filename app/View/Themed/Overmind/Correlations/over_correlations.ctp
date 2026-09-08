<?php
/*
 * Over-correlating values index.
 *
 */

$canExclude = $this->Acl->canAccess('correlation_exclusions', 'add');

// Header section
$this->set('headerTitle', __('Over-correlating values'));
$this->set('headerDescription', __('Values that correlate so often they are blocked from generating further correlations.'));

$this->set('headerActions', [
    [
        'type' => 'action',
        'label' => __('Regenerate occurrence counts'),
        'icon' => 'sync',
        'url' => $baseurl . '/correlations/generateOccurrences',
    ],
]);

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'OverCorrelatingValue.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('Value'),
        'data_path' => 'OverCorrelatingValue.value',
        'element' => 'custom',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) use ($baseurl) {
            $value = Hash::get($row, 'OverCorrelatingValue.value');
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
    ],
    [
        'name' => __('Blocked by threshold'),
        'data_path' => 'OverCorrelatingValue.over_correlation',
        'element' => 'custom',
        'class' => 'shortish',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) {
            $blocked = !empty(Hash::get($row, 'OverCorrelatingValue.over_correlation'));
            if ($blocked) {
                return '<span class="badge text-bg-warning">'
                    . '<i class="fas fa-triangle-exclamation me-1"></i>' . h(__('Blocked')) . '</span>';
            }
            return '<span class="text-muted">&mdash;</span>';
        },
    ],
    [
        'name' => __('Excluded by exclusion list'),
        'data_path' => 'OverCorrelatingValue.excluded',
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) {
            $excluded = !empty(Hash::get($row, 'OverCorrelatingValue.excluded'));
            if ($excluded) {
                return '<span class="badge text-bg-danger">'
                    . '<i class="fas fa-ban me-1"></i>' . h(__('Excluded')) . '</span>';
            }
            return '<span class="text-muted">&mdash;</span>';
        },
    ],
    [
        'name' => __('Occurrences'),
        'data_path' => 'OverCorrelatingValue.occurrence',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Actions'),
        'data_path' => 'OverCorrelatingValue.value',
        'element' => 'custom',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) use ($baseurl, $canExclude) {
            $value = Hash::get($row, 'OverCorrelatingValue.value');
            $excluded = !empty(Hash::get($row, 'OverCorrelatingValue.excluded'));
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
    ],
];

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'skip_pagination' => true,
            'filter_bar' => [
                // Drive the bar against overCorrelations instead of /index.
                'action' => 'overCorrelations',
                'children' => [
                    [
                        'type' => 'search',
                        'mode' => 'quickFilter',
                        'name' => 'quickFilter',
                        'placeholder' => __('Enter value to search'),
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'name' => 'scope',
                                'label' => __('Correlation status'),
                                'options' => [
                                    '' => __('All'),
                                    'over_correlating' => __('Over-correlating'),
                                    'not_over_correlating' => __('Not over-correlating'),
                                ],
                            ],
                        ],
                    ],
                ],
            ],
            'fields' => $fields,
        ],
    ],
    'item_url' => '/correlations'
]);
