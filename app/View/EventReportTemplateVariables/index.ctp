<?php
    $fields = [
        [
            'name' => __('Name'),
            'sort' => 'EventReportTemplateVariable.name',
            'data_path' => 'EventReportTemplateVariable.name',
            'element' => 'custom',
            'function' => function (array $templateVariable) {
                return sprintf('<div style="white-space: nowrap;">%s%s%s</div>', 
                    '<code class="curly-char">{{ </code><b>',
                    h($templateVariable['EventReportTemplateVariable']['name']),
                    '</b><code class="curly-char"> }}</code>',
            );
            }
        ],
        [
            'name' => __('Value'),
            'sort' => 'EventReportTemplateVariable.value',
            'data_path' => 'EventReportTemplateVariable.value',
            'element' => 'custom',
            'function' => function (array $templateVariable) {
                $text = $templateVariable['EventReportTemplateVariable']['value'];
                $maxLength = 1000;
                $maxLines = 20;
                $truncated = false;
                if (mb_strlen($text) > $maxLength) {
                    $text = mb_substr($text, 0, $maxLength);
                    $truncated = true;
                }
            
                if (substr_count($text, "\n") > $maxLines) {
                    $lines = explode("\n", $text);
                    $text = implode("\n", array_slice($lines, 0, $maxLines));
                    $truncated = true;
                }
                $text = !$truncated ? $text : $text . ' …';
                return sprintf('<pre>%s</pre>', h($text));
            }
        ],
    ];

    echo $this->element('genericElements/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $data,
                'top_bar' => [
                    'pull' => 'right',
                    'children' => [
                        [
                            'type' => 'simple',
                            'children' => [
                                [
                                    'text' => __('Add'),
                                    'fa-icon' => 'plus',
                                    'url' => $baseurl . '/eventReportTemplateVariables/add',
                                    'requirement' => $isSiteAdmin,
                                ]
                            ]
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
                'title' => empty($ajax) ? __('Event Report Template Variable index') : false,
                'actions' => [
                    [
                        'url' => $baseurl . '/eventReportTemplateVariables/edit',
                        'url_params_data_paths' => ['EventReportTemplateVariable.id'],
                        'icon' => 'edit'
                    ],
                    [
                        'onclick' => sprintf(
                            'openGenericModal(\'%s/eventReportTemplateVariables/delete/[onclick_params_data_path]\');',
                            $baseurl
                        ),
                        'onclick_params_data_path' => 'EventReportTemplateVariable.id',
                        'icon' => 'trash'
                    ]
                ]
            ]
        ]
    ]);

?>
