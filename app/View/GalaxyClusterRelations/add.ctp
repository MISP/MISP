<?php
    $fieldDesc = array(
        'referenced_galaxy_cluster_type' => __('relationships which can be used to link clusters together and explain the context of the relationship.'),
    );
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => ($action == 'add' ? __('Add') : __('Edit')) . ' ' . __('Galaxy Cluster Relationship'),
            'fields' => array(
                array(
                    'field' => 'galaxy_cluster_uuid',
                    'label' => __('Source UUID'),
                    'type' => 'text',
                    'picker' => array(
                        'text' => __('Pick source cluster'),
                        'function' => 'pickerSource',
                    )
                ),
                array(
                    'field' => 'referenced_galaxy_cluster_uuid',
                    'label' => __('Target UUID'),
                    'type' => 'text',
                    'picker' => array(
                        'text' => __('Pick target cluster'),
                        'function' => 'pickerTarget',
                        )
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
                    'field' => 'referenced_galaxy_cluster_type',
                    'label' => __('Relationship Type'),
                    'placeholder' => __('is-similar'),
                    'type' => 'text',
                    'picker' => array(
                        'text' => __('Pick type'),
                        'function' => 'pickerTypes',
                    )
                ),
                array(
                    'field' => 'tags',
                    'label' => __('Tag list'),
                    'type' => 'textarea',
                    'placeholder' => 'estimative-language:likelihood-probability="very-likely", false-positive:risk="low"',
                    'picker' => array(
                        'text' => __('Pick tags'),
                        'function' => 'pickerTags',
                    )
                ),
            ),
            'submit' => array(
                'ajaxSubmit' => ''
            )
        ),
        'fieldDesc' => $fieldDesc,
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxy_cluster_relations', 'menuItem' => $this->action === 'add' ? 'add' : 'edit'));
?>

<script type="text/javascript">
    $('#GalaxyClusterRelationDistribution').change(function() {
        checkSharingGroup('GalaxyClusterRelation');
    });

    existingRelationTypes = <?= json_encode(array_values($existingRelations)) ?> ;

    $(document).ready(function() {
        checkSharingGroup('GalaxyClusterRelation');
        $('[data-toggle=\"json\"]').each(function() {
        $(this).attr('data-toggle', '')
            .html(syntaxHighlightJson($(this).text().trim()));
        });
    });
    function pickerSource() {
        $(this).data('popover-no-submit', true);
        $(this).data('popover-callback-function', setSourceUUIDAfterSelect);
        var target_id = 0;
        var target_type = 'galaxyClusterRelation';
        var noGalaxyMatrix = 1;
        popoverPopup(this, target_id + '/' + target_type + '/' + noGalaxyMatrix, 'galaxies', 'selectGalaxyNamespace');
    }
    function pickerTarget() {
        $(this).data('popover-no-submit', true);
        $(this).data('popover-callback-function', setTargetUUIDAfterSelect);
        var target_id = 0;
        var target_type = 'galaxyClusterRelation';
        var noGalaxyMatrix = 1;
        popoverPopup(this, target_id + '/' + target_type + '/' + noGalaxyMatrix, 'galaxies', 'selectGalaxyNamespace');
    }
    function pickerTags() {
        $(this).data('popover-no-submit', true);
        $(this).data('popover-callback-function', setTagsAfterSelect);
        var target_id = 0;
        var target_type = 'galaxyClusterRelation';
        popoverPopup(this, target_id + '/' + target_type, 'tags', 'selectTaxonomy')
    }
    function pickerTypes() {
        var $select = $('<select id="pickerTypeSelect"/>');
        existingRelationTypes.forEach(function(type) {
            $select.append($('<option/>').val(type).text(type))
        })
        var html = '<div>' + $select[0].outerHTML + '</div>';
        var that = this
        openPopover(this, html, false, 'right', function($popover) {
            $popover.find('select').chosen({
                width: '300px',
            }).on('change', function(evt, param) {
                addPickedTypes()
                $(that).popover('hide')
            });
        });
    }
    function addPickedTypes() {
        $('#GalaxyClusterRelationReferencedGalaxyClusterType').val($('#pickerTypeSelect').val());
    }
    function setSourceUUIDAfterSelect(selected, additionalData) {
        selectedUUID = additionalData.itemOptions[selected].uuid;
        $('#GalaxyClusterRelationGalaxyClusterUuid').val(selectedUUID);
    }
    function setTargetUUIDAfterSelect(selected, additionalData) {
        selectedUUID = additionalData.itemOptions[selected].uuid;
        $('#GalaxyClusterRelationReferencedGalaxyClusterUuid').val(selectedUUID);
    }
    function setTagsAfterSelect(selected, additionalData) {
        selectedTags = [];
        selected.forEach(function(selection) {
            selectedTags.push(additionalData.itemOptions[selection].tag_name);
        });
        $('#GalaxyClusterRelationTags').val(selectedTags.join(', '));
    }
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
