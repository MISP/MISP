<?php
/*
 * The filter bar of the log indexes (application / audit / access): the index
 * filter bar in its deferred mode.
 *
 * Log tables hold millions of rows and a multi-column LIKE cannot use an
 * index, so nothing here queries on its own: each filter waits in the Filters
 * panel's draft and one Apply runs them together, the search box's Enter
 * included.
 *
 * Filters travel in the query string: a named URL segment cannot carry a '/',
 * and searching the access log means searching URLs. The views wrap this bar
 * and their results in `[data-ifp-scope]`, the results in `[data-ifp-results]`.
 *
 * Expected variables:
 *  - $item_url : base path, e.g. '/admin/access_logs'
 *  - $search   : ['placeholder' => <string>] for the free-text box
 *  - $fields   : [{name, label, type: select|text|number|date, options,
 *                placeholder, help, step, group, requirement}]; a select
 *                becomes a picker, a date the time picker, the rest a value
 *  - $rows     : the page's rows, for the count beside the chips
 *  - $pager    : optional pager element, for a log paged without a total
 */
$presets = [
    ['value' => '1h', 'label' => __('1h'), 'title' => __('last hour')],
    ['value' => '1d', 'label' => __('24h'), 'title' => __('last 24 hours')],
    ['value' => '7d', 'label' => __('7d'), 'title' => __('last 7 days')],
    ['value' => '30d', 'label' => __('30d'), 'title' => __('last 30 days')],
    ['value' => '90d', 'label' => __('90d'), 'title' => __('last 90 days')],
];
$presetTitles = array_column($presets, 'title', 'value');
$timeLabel = function ($value) use ($presetTitles) {
    if (isset($presetTitles[$value])) {
        return $presetTitles[$value];
    }
    $range = explode('||', (string)$value, 2);
    if (count($range) === 2) {
        return ($range[0] === '0' ? '…' : substr($range[0], 0, 10)) . ' – ' . ($range[1] === '' ? '…' : substr($range[1], 0, 10));
    }
    return sprintf(__('since %s'), $value);
};

$children = [[
    'type' => 'search',
    'placeholder' => $search['placeholder'] ?? __('Search all entries…'),
    'mode' => 'quickFilter',
]];
$chipValues = [];
foreach (($fields ?? []) as $field) {
    if (isset($field['requirement']) && !$field['requirement']) {
        continue;
    }
    $type = $field['type'] ?? 'text';
    $common = [
        'name' => $field['name'],
        'label' => $field['label'] ?? $field['name'],
        'group' => $field['group'] ?? null,
    ];
    if ($type === 'select') {
        $children[] = $common + [
            'type' => 'dropdown',
            'options' => $field['options'] ?? [],
            'help' => $field['help'] ?? null,
        ];
    } elseif ($type === 'date') {
        $children[] = $common + [
            'type' => 'time',
            'icon' => 'far fa-clock',
            'fields' => [['name' => $field['name'], 'label' => $common['label']]],
            'presets' => $presets,
        ];
        $chipValues[$field['name']] = $timeLabel;
    } else {
        $children[] = $common + [
            'type' => 'value',
            'input' => $type,
            'placeholder' => $field['placeholder'] ?? null,
            'step' => $field['step'] ?? null,
            'hint' => $field['help'] ?? null,
        ];
    }
}

echo $this->element('genericElementsBS5/IndexTable/filter_bar', [
    'scaffold_data' => [
        'data' => $rows ?? [],
        'filter_bar' => [
            'apply' => 'deferred',
            'transport' => 'query',
            'view_switch' => false,
            'pager' => $pager ?? null,
            'children' => $children,
            'chips' => ['values' => $chipValues],
        ],
    ],
    'item_url' => $item_url,
]);
