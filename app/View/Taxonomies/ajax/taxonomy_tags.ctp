<?php
$fields = [
    [
        'name' => __('Name'),
        'sort' => 'tag',
        'class' => 'short',
        'data_path' => 'tag'
    ],
    [
        'name' => __('Expanded'),
        'sort' => 'expanded',
        'data_path' => 'expanded'
    ],
    [
        'name' => __('Numerical Value'),
        'sort' => 'numerical_value',
        'class' => 'short',
        'data_path' => 'numerical_value',
        'element' => 'custom',
        'function' => function (array $row) {
            $html = isset($row['numerical_value']) ? h($row['numerical_value']) : '';
            if (isset($row['original_numerical_value'])) {
                $html .= sprintf(' <i class="%s" title="%s" data-value-overriden="1"></i>',
                    $this->FontAwesome->getClass('exclamation-triangle'),
                    __('Numerical value overridden by userSetting.&#10;Original numerical_value = %s',
                        empty($row['original_numerical_value']) ? __('None') : h($row['original_numerical_value'])
                    )
                );
            }
            return $html;
        }
    ],
    [
        'name' => __('# Events'),
        'sort' => 'events',
        'class' => 'short',
        'data_path' => 'events',
        'element' => 'links',
        'url' => '/events/index',
        'url_params_data_paths' => ['searchtag' => 'existing_tag.Tag.id'],
    ],
    [
        'name' => __('# Attributes'),
        'sort' => 'attributes',
        'class' => 'short',
        'data_path' => 'attributes',
        'element' => 'links',
        'url' => '/attributes/search',
        'url_params_data_paths' => ['tags' => 'existing_tag.Tag.id'],
    ],
    [
        'name' => __('Tag'),
        'sort' => 'tag',
        'class' => 'short',
        'data_path' => 'existing_tag',
        'element' => 'tagSimple',
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'existing_tag.Tag.hide_tag',
        'class' => 'short',
        'data_path' => 'existing_tag.Tag.hide_tag',
        'element' => 'booleanOrNA',
        'boolean_reverse' => true
    ],
];

$actions = [
    [
        'title' => __('View Correlation Graph'),
        'icon' => 'share-alt',
        'url' => $baseurl . '/tags/viewGraph',
        'url_params_data_paths' => ['existing_tag.Tag.id'],
        'postLinkConfirm' => __('Are you sure you want to create this tag?'),
        'requirement' => $isAclTagger && $taxonomy['enabled'],
    ],
    [
        'title' => __('Create Tag'),
        'icon' => 'plus',
        'onclick' => 'openGenericModal(\'' . $baseurl . sprintf('/taxonomies/addTag/taxonomy_id:%s/[onclick_params_data_path]\');', $taxonomy['id']),
        'onclick_params_data_path' => ['name' => 'tag'],
        'complex_requirement' => array(
            'function' => function ($row, $options) {
                return $options['isAclTagger'] && $options['taxonomyEnabled'] && empty($row['existing_tag']);
            },
            'options' => array(
                'isAclTagger' => $isAclTagger,
                'taxonomyEnabled' => $taxonomy['enabled']
            )
        ),
    ],
    [
        'title' => __('Enable Tag'),
        'icon' => 'play',
        'onclick' => 'openGenericModal(\'' . $baseurl . sprintf('/taxonomies/addTag/taxonomy_id:%s/enable:1/[onclick_params_data_path]\');', $taxonomy['id']),
        'onclick_params_data_path' => ['name' => 'tag'],
        'complex_requirement' => array(
            'function' => function ($row, $options) {
                return $options['isAclTagger'] && $options['taxonomyEnabled'] && !empty($row['existing_tag'] && $options['datapath']['hide_tag']);
            },
            'options' => array(
                'isAclTagger' => $isAclTagger,
                'taxonomyEnabled' => $taxonomy['enabled'],
                'datapath' => array(
                    'hide_tag' => 'existing_tag.Tag.hide_tag'
                )
            )
        ),
    ],
    [
        'title' => __('Update Tag'),
        'icon' => 'sync',
        'onclick' => 'openGenericModal(\'' . $baseurl . sprintf('/taxonomies/addTag/taxonomy_id:%s/update:1/[onclick_params_data_path]\');', $taxonomy['id']),
        'onclick_params_data_path' => ['name' => 'tag'],
        'complex_requirement' => array(
            'function' => function ($row, $options) {
                return $options['isAclTagger'] && $options['taxonomyEnabled'] &&
                    isset($row['existing_tag']) && $row['existing_tag'] !== false && !$options['datapath']['hide_tag'];
            },
            'options' => array(
                'isAclTagger' => $isAclTagger,
                'taxonomyEnabled' => $taxonomy['enabled'],
                'datapath' => array(
                    'hide_tag' => 'existing_tag.Tag.hide_tag'
                )
            )
        ),
    ],
    [
        'title' => __('Disable Tag'),
        'icon' => 'stop',
        'onclick' => 'openGenericModal(\'' . $baseurl . sprintf('/taxonomies/disableTag/taxonomy_id:%s/[onclick_params_data_path]\');', $taxonomy['id']),
        'onclick_params_data_path' => ['name' => 'tag'],
        'complex_requirement' => array(
            'function' => function ($row, $options) {
                return $options['isAclTagger'] && $options['taxonomyEnabled'] &&
                    isset($row['existing_tag']) && $row['existing_tag'] !== false && !$options['datapath']['hide_tag'];
            },
            'options' => array(
                'isAclTagger' => $isAclTagger,
                'taxonomyEnabled' => $taxonomy['enabled'],
                'datapath' => array(
                    'hide_tag' => 'existing_tag.Tag.hide_tag'
                )
            )
        ),
    ],
];

echo $this->element('/genericElements/IndexTable/scaffold', ['scaffold_data' => ['data' => [
    'data' => $entries,
    'stupid_pagination' => 1,
    'top_bar' => [
        'children' => [
            [
                'type' => 'simple',
                'children' => [
                    [
                        'url' => $baseurl . sprintf('/taxonomies/view/%s', $taxonomy['id']),
                        'text' => __('All'),
                        'active' => !isset($passedArgsArray['enabled']),
                    ],
                    [
                        'url' => $baseurl . sprintf('/taxonomies/view/%s/enabled:1', $taxonomy['id']),
                        'text' => __('Enabled'),
                        'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "1",
                    ],
                    [
                        'url' => $baseurl . sprintf('/taxonomies/view/%s/enabled:0', $taxonomy['id']),
                        'text' => __('Disabled'),
                        'active' => isset($passedArgsArray['enabled']) && $passedArgsArray['enabled'] === "0",
                    ]
                ]
            ],
            [
                'type' => 'search',
                'button' => __('Filter'),
                'placeholder' => __('Enter value to search'),
                'searchKey' => 'filter',
                'cancel' => array(
                    'fa-icon' => 'times',
                    'title' => __('Remove filters'),
                    'onClick' => 'cancelSearch',
                )
            ]
        ]
    ],
    'fields' => $fields,
    'actions' => $actions,
    'paginatorOptions' => [
        'url' => [$taxonomy['id']]
    ],
    'persistUrlParams' => ['filter']
],
    'containerId' => 'preview_taxonomy_tags_container'
]]);
