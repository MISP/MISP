<?php
echo $this->element('/genericElements/IndexTable/index_table', array(
    'data' => array(
        'paginatorOptions' => array(
            'update' => '#elements_div',
        ),
        'data' => $elements,
        'top_bar' => array(
            'children' => array(
                array(
                    'type' => 'simple',
                    'children' => array(
                        array(
                            'onClick' => 'openGenericModal',
                            'onClickParams' => [$baseurl . '/galaxy_elements/flattenJson/' . h($clusterId)],
                            'active' => true,
                            'text' => __('Add JSON'),
                            'title' => __('The provided JSON will be converted into Galaxy Cluster Elements'),
                            'fa-icon' => 'plus',
                            'requirement' => $canModify,
                        ),
                    )
                ),
                array(
                    'type' => 'simple',
                    'children' => array(
                        array(
                            'active' => $context === 'all',
                            'url' => sprintf('%s/galaxy_elements/index/%s/context:all', $baseurl, $clusterId),
                            'text' => __('Tabular view'),
                        ),
                        array(
                            'active' => $context === 'treeView',
                            'url' => sprintf('%s/galaxy_elements/index/%s/context:treeView', $baseurl, $clusterId),
                            'text' => __('Tree view'),
                        ),
                    )
                ),
                array(
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'value'
                )
            )
        ),
        'primary_id_path' => 'GalaxyElement.id',
        'fields' => array(
            array(
                'name' => __('Key'),
                'data_path' => 'GalaxyElement.key',
                'sort' => 'key',
            ),
            array(
                'name' => __('Value'),
                'data_path' => 'GalaxyElement.value',
                'sort' => 'value',
                'element' => 'galaxy_element_value',
                'elementParams' => array(
                    'data_path_key' =>'GalaxyElement.key'
                ),
            ),
        ),
        'actions' => array(
            array(
                'title' => __('Delete'),
                'icon' => 'trash',
                'onclick' => 'simplePopup(\'' . $baseurl . '/galaxy_elements/delete/[onclick_params_data_path]\');',
                'onclick_params_data_path' => 'GalaxyElement.id',
                'requirement' => $canModify,
            )
        )
    )
));
echo $this->Js->writeBuffer();