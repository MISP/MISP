<?php
    $fieldDesc = array();
    $fieldDesc['uuids'] = __('Enter a single or a list of UUIDs');
    $fieldDesc['cluster_orgc'] = __('(Optional) The organisation that the event is associated with');
    $fieldDesc['cluster_info'] = __('(Optional) The cluster value that you would like to block');
    $fieldDesc['comment'] = __('(Optional) Any comments you would like to add regarding this (or these) entries');
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'model' => 'GalaxyClusterBlocklist',
            'title' => $action == 'add' ? __('Add block entry for Galaxy Cluster') : __('Edit block entry for Galaxy Cluster'),
            'fields' => array(
                array(
                    'disabled' => $action != 'add' ? 'disabled' : '',
                    'field' => 'uuids',
                    'class' => 'span6',
                    'label' => __('Cluster UUID'),
                    'type' => 'textarea',
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['cluster_uuid']) ? $blockEntry['GalaxyClusterBlocklist']['cluster_uuid'] : '',
                    'picker' => array(
                        'text' => __('Pick target cluster'),
                        'function' => 'pickerTarget',
                    ),
                ),
                array(
                    'field' => 'cluster_orgc',
                    'label' => __('Creating organisation'),
                    'class' => 'span6',
                    'type' => 'text',
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['cluster_orgc']) ? $blockEntry['GalaxyClusterBlocklist']['cluster_orgc'] : ''
                ),
                array(
                    'field' => 'cluster_info',
                    'label' => __('Cluster value'),
                    'class' => 'span6',
                    'type' => 'text',
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['cluster_info']) ? $blockEntry['GalaxyClusterBlocklist']['cluster_info'] : ''
                ),
                array(
                    'field' => 'comment',
                    'label' => __('Comment'),
                    'class' => 'span6',
                    'type' => 'text',
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['comment']) ? $blockEntry['GalaxyClusterBlocklist']['comment'] : ''
                ),
            ),
            'submit' => array(
                'ajaxSubmit' => ''
            )
        ),
        'fieldDesc' => $fieldDesc
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'index_blocklist'));
?>

<script type="text/javascript">
    function pickerTarget() {
        $(this).data('popover-no-submit', true);
        $(this).data('popover-callback-function', setTargetUUIDAfterSelect);
        var target_id = 0;
        var target_type = 'galaxyClusterRelation';
        var noGalaxyMatrix = 1;
        popoverPopup(this, target_id + '/' + target_type + '/' + noGalaxyMatrix, 'galaxies', 'selectGalaxyNamespace');
    }
    function setTargetUUIDAfterSelect(selected, additionalData) {
        selectedUUID = additionalData.itemOptions[selected].uuid;
        $('#GalaxyClusterBlocklistUuids').val(selectedUUID);
    }
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
