<?php
$fields = [
    [
        'name' => __('Object relation'),
        'sort' => 'ObjectTemplateElement.object_relation',
        'data_path' => 'ObjectTemplateElement.object_relation, ObjectTemplateElement.description',
        'element' => 'name_description',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Type'),
        'sort' => 'ObjectTemplateElement.type',
        'data_path' => 'ObjectTemplateElement.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Multiple'),
        'sort' => 'ObjectTemplateElement.multiple',
        'data_path' => 'ObjectTemplateElement.multiple',
        'element' => 'multiple',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Correlation'),
        'sort' => 'ObjectTemplateElement.disable_correlation',
        'data_path' => 'ObjectTemplateElement.disable_correlation',
        'element' => 'correlate',
        'boolean_reverse' => true,
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('UI-priority'),
        'sort' => 'ObjectTemplateElement.ui-priority',
        'data_path' => 'ObjectTemplateElement.ui-priority',
        'element' => 'count',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Categories'),
        'data_path' => 'ObjectTemplateElement.category',
        'element' => 'category',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Sane defaults'),
        'data_path' => 'ObjectTemplateElement.sane_default',
        'card_section' => 'extra',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('List of valid Values'),
        'data_path' => 'ObjectTemplateElement.values_list',
        'element' => 'object_template_element_values_list',
        'card_section' => 'link',
        'display_in' => ['table', 'card']
    ],
];

/**
 * Scaffold
 */
echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $list,
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    // Has to be implemented in the controller first
                    // [
                    //     'type' => 'search',
                    //     'button' => __('Search'),
                    //     'placeholder' => __('Search by element name'),
                    //     'name'          => 'quickFilter',
                    //     'mode'      => 'quickFilter',
                    // ]
                ],
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/objectTemplateElements'
]);

?>