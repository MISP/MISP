<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => $action == 'add' ? __('Add Galaxy Cluster Relationships') : __('Edit Galaxy Cluster Relationships'),
            'fields' => array(
                array(
                    'field' => 'galaxy_cluster_uuid',
                    'label' => __('Source UUID'),
                    'type' => 'text',
                    'stayInLine' => true
                ),
                array(
                    'field' => 'distribution',
                    'options' => $distributionLevels,
                    'default' => isset($cluster['GalaxyCluster']['distribution']) ? $cluster['GalaxyCluster']['distribution'] : $initialDistribution,
                    'default' => $initialDistribution,
                    'stayInLine' => 1
                ),
                array(
                    'field' => 'sharing_group_id',
                    'options' => $sharingGroups,
                    'label' => __("Sharing Group")
                ),
                array(
                    'field' => 'referenced_galaxy_cluster_uuid',
                    'label' => __('Target UUID'),
                    'type' => 'text',
                ),
                array(
                    'field' => 'referenced_galaxy_cluster_type',
                    'label' => __('Relationship Type'),
                    'type' => 'text',
                ),
                array(
                    'field' => 'tags',
                    'label' => __('Tags'),
                    'type' => 'text',
                ),
            ),
            'submit' => array(
                'ajaxSubmit' => ''
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxy_cluster_relations', 'menuItem' => $this->action === 'add' ? 'add' : 'edit'));
?>

<script type="text/javascript">
    $('#GalaxyClusterRelationDistribution').change(function() {
        checkSharingGroup('GalaxyClusterRelation');
    });

    $(document).ready(function() {
        checkSharingGroup('GalaxyClusterRelation');
        $('[data-toggle=\"json\"]').each(function() {
        $(this).attr('data-toggle', '')
            .html(syntaxHighlightJson($(this).text().trim()));
        });
    });
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts