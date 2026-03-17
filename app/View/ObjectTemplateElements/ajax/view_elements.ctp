<?php
    echo '<div>';
    echo $this->element('/genericElements/IndexTable/index_table', [
        'data' => [
            'data' => $list,
            'fields' => [
                [
                    'name' => __('Object relation'),
                    'sort' => 'ObjectTemplateElement.object_relation',
                    'class' => 'short bold',
                    'data_path' => 'ObjectTemplateElement.object_relation',
                ],
                [
                    'name' => __('Type'),
                    'sort' => 'ObjectTemplateElement.type',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplateElement.type',
                ],
                [
                    'name' => __('Multiple'),
                    'sort' => 'ObjectTemplateElement.multiple',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplateElement.multiple',
                ],
                [
                    'name' => __('UI-priority'),
                    'sort' => 'ObjectTemplateElement.ui-priority',
                    'class' => 'short',
                    'data_path' => 'ObjectTemplateElement.ui-priority',
                ],
                [
                    'name' => __('Description'),
                    'sort' => 'ObjectTemplateElement.description',
                    'class' => 'long',
                    'data_path' => 'ObjectTemplateElement.description',
                ],
                [
                    'name' => __('Categories'),
                    'class' => 'short',
                    'data_path' => 'ObjectTemplateElement.category',
                ],
                [
                    'name' => __('Sane defaults'),
                    'class' => 'long',
                    'data_path' => 'ObjectTemplateElement.sane_default',
                ],
                [
                    'name' => __('List of valid Values'),
                    'class' => 'short',
                    'element' => 'object_template_element_values_list',
                    'data_path' => 'ObjectTemplateElement.values_list',
                ],
                [
                    'name' => __('Disable correlation'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'ObjectTemplateElement.disable_correlation',
                ]
            ]
        ]
    ]);
    echo '</div>';
?>
