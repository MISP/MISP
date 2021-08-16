<?php
$indexOptions = array(
    'containerId' => 'elements',
    'data' => array(
        'data' => $elements,
        'top_bar' => array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'active' => $context === 'all',
                            'text' => __('Tabular view'),
                            'onClick' => 'runIndexQuickFilter',
                            'onClickParams' => [
                                h($clusterId) . '/context:all',
                                $baseurl . '/galaxy_elements/index',
                                '#elements_content'
                            ],
                        ),
                        array(
                            'active' => $context === 'JSONView',
                            'text' => __('JSON view'),
                            'onClick' => 'runIndexQuickFilter',
                            'onClickParams' => [
                                h($clusterId) . '/context:JSONView',
                                $baseurl . '/galaxy_elements/index',
                                '#elements_content'
                            ],
                        ),
                    )
                ),
                array(
                    'type' => 'simple',
                    'children' => array(
                        array(
                            'onClick' => 'openGenericModal',
                            'onClickParams' => [$baseurl . '/galaxy_elements/flattenJson/' . h($clusterId)],
                            'active' => true,
                            'text' => __('Add JSON as cluster\'s elements'),
                            'title' => __('The provided JSON will be converted into Galaxy Cluster Elements'),
                            'fa-icon' => 'plus',
                            'requirement' => $canModify && ($context === 'JSONView'),
                        ),
                    )
                ),
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
);

if ($context == 'JSONView') {
    $indexOptions['data']['fields'] = [];
    $indexOptions['data']['data'] = [];
    $indexOptions['data']['skip_pagination'] = true;
    $indexOptions['data']['actions'] = [];
}

echo $this->element('/genericElements/IndexTable/index_table', $indexOptions);
if ($context == 'JSONView') {
    echo sprintf('<div id="elementJSONDiv" class="well well-small">%s</div>', json_encode(h($JSONElements)));
}
?>

<script>
    var $jsondiv = $('#elementJSONDiv');
    if ($jsondiv.length > 0) {
        $jsondiv.html(syntaxHighlightJson($jsondiv.text(), 8));
    }
</script>
