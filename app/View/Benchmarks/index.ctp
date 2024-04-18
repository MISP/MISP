<?php
    $passedArgsArray = json_decode($passedArgs, true);
    $fields = [
        [
            'name' => __('Date'),
            'sort' => 'date',
            'data_path' => 'date'
        ],
        [
            'name' => __('scope'),
            'sort' => 'scope',
            'data_path' => 'scope'
        ],
        [
            'name' => __('Key'),
            'sort' => 'key',
            'data_path' => 'text'
        ],
        [
            'name' => __('field'),
            'sort' => 'field',
            'data_path' => 'field'
        ],
        [
            'name' => __('Value'),
            'element' => 'custom',
            'function' => function($row) {
                return empty($row['unit']) ? h($row['value']) : h($row['value'] . ' ' . $row['unit']);
            },
            'sort' => 'value'
        ]
    ];
    $quick_filters = [];
    foreach ($settings as $key => $setting_data) {
        $temp = $filters;
        $url = $baseurl . '/benchmarks/index';
        foreach ($temp as $s => $v) {
            if ($v && $s != $key) {
                if (is_array($v)) {
                    foreach ($v as $multi_v) {
                        $url .= '/' . $s . '[]:' . $multi_v;
                    }
                } else {
                    $url .= '/' . $s . ':' . $v;
                }
                
            }
        }
        if ($key != 'average' && $key != 'aggregate') {
            $quick_filters[$key]['all'] = [
                'url' => h($url),
                'text' => __('All'),
                'active' => !$filters[$key],
                'style' => 'display:inline;'
            ];
        }
        foreach ($setting_data as $setting_element) {
            $text = $setting_element;
            if ($key == 'average') {
                $text = $setting_element ? 'average / request' : 'total';
            }
            if ($key == 'aggregate') {
                $text = $setting_element ? 'aggregate' : 'daily';
            }
            $quick_filters[$key][] = [
                'url' => h($url . '/' . $key . ':' . $setting_element),
                'text' => $text,
                'active' => $filters[$key] == $setting_element,
                'style' => 'display:inline;'
            ];
        }
    }
    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'passedArgsArray' => $passedArgsArray,
            'data' => [
                'persistUrlParams' => array_keys($settings),
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'children' => $quick_filters['scope']
                        ],
                        [
                            'children' => $quick_filters['field']
                        ],
                        [
                            'children' => $quick_filters['average']
                        ],
                        [
                            'children' => $quick_filters['aggregate']
                        ],
                        [
                            'type' => 'search',
                            'button' => __('Filter'),
                            'placeholder' => __('Enter value to search'),
                            'data' => '',
                            'searchKey' => 'quickFilter'
                        ]
                    ]
                ],
                'fields' => $fields,
                'title' => empty($ajax) ? __('Benchmark results') : false,
                'description' => empty($ajax) ? __('Results of the collected benchmarks. You can filter it further by passing the limit, scope, field parameters.') : false,
            ]
        ]
    ]);

?>
