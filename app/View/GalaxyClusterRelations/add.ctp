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
                    'stayInLine' => 1
                ),
                sprintf('<button id="btnPickTarget" type="button" style="margin-top: 25px;">%s</button>', __('Pick target cluster')),
                array(
                    'field' => 'referenced_galaxy_cluster_type',
                    'label' => __('Relationship Type'),
                    'type' => 'text',
                ),
                array(
                    'field' => 'tags',
                    'label' => __('Tag list'),
                    'type' => 'textarea',
                    'placeholder' => 'estimative-language:likelihood-probability="very-likely", false-positive:risk="low"',
                    'stayInLine' => 1
                ),
                sprintf('<button id="btnPickTag" type="button" style="margin-top: 25px;">%s</button>', __('Pick tags')),
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
        $('#btnPickTarget').click(function() {
            $(this).data('popover-no-submit', true);
            $(this).data('popover-callback-function', setTargetUUIDAfterSelect);
            var target_id = 0;
            var target_type = 'galaxyClusterRelation';
            popoverPopup(this, target_id + '/' + target_type, 'galaxies', 'selectGalaxyNamespace');
        });
        $('#btnPickTag').click(function() {
            $(this).data('popover-no-submit', true);
            $(this).data('popover-callback-function', setTagsAfterSelect);
            var target_id = 0;
            var target_type = 'galaxyClusterRelation';
            popoverPopup(this, target_id + '/' + target_type, 'tags', 'selectTaxonomy')
        });
    });
    function setTargetUUIDAfterSelect(selected, additionalData){
        selectedUUID = additionalData.itemOptions[selected].uuid;
        $('#GalaxyClusterRelationReferencedGalaxyClusterUuid').val(selectedUUID);
    }
    function setTagsAfterSelect(selected, additionalData){
        selectedTags = [];
        selected.forEach(function(selection) {
            selectedTags.push(additionalData.itemOptions[selection].tag_name);
        });
        $('#GalaxyClusterRelationTags').val(selectedTags.join(', '));
    }
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts