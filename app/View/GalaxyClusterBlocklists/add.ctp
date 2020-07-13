<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'model' => 'GalaxyClusterBlocklist',
            'title' => $action == 'add' ? __('Add block entry for Galaxy Cluster') : __('Edit block entry for Galaxy Cluster'),
            'fields' => array(
                array(
                    'field' => 'cluster_uuid',
                    'label' => __('Cluster UUID'),
                    'type' => 'textarea',
                    'help' => _('Enter a single or a list of UUIDs'),
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['cluster_uuid']) ? $blockEntry['GalaxyClusterBlocklist']['cluster_uuid'] : ''
                ),
                array(
                    'field' => 'cluster_orgc',
                    'label' => __('Creating organisation'),
                    'type' => 'text',
                    'help' => _('(Optional) The organisation that the event is associated with'),
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['cluster_orgc']) ? $blockEntry['GalaxyClusterBlocklist']['cluster_orgc'] : ''
                ),
                array(
                    'field' => 'cluster_info',
                    'label' => __('Cluster value'),
                    'type' => 'text',
                    'help' => _('(Optional) The cluster value that you would like to block'),
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['cluster_info']) ? $blockEntry['GalaxyClusterBlocklist']['cluster_info'] : ''
                ),
                array(
                    'field' => 'comment',
                    'label' => __('Comment'),
                    'type' => 'text',
                    'help' => _('(Optional) Any comments you would like to add regarding this (or these) entries'),
                    'default' => isset($blockEntry['GalaxyClusterBlocklist']['comment']) ? $blockEntry['GalaxyClusterBlocklist']['comment'] : ''
                ),
            ),
            'submit' => array(
                'ajaxSubmit' => ''
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => 'index_blocklist'));
?>

<script type="text/javascript">
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
