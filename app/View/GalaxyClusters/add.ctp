<?php
    $modelForForm = 'GalaxyCluster';
    $origCluster = isset($origCluster) ? $origCluster : array();
    $origClusterHtmlPreview = '';
    if (isset($origClusterMeta)) {
        foreach ($origClusterMeta as $key => $value) {
            if (is_array($value)) {
                $origClusterHtmlPreview .= sprintf('<div><b>%s: </b><div data-toggle="json" class="large-left-margin">%s</div></div>', h($key), json_encode($value));
            } else {
                $origClusterHtmlPreview .= sprintf('<div><b>%s: </b>%s</div>', h($key), h($value));
            }
        }
    }

    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => $action == 'add' ? __('Add Galaxy Cluster') : __('Edit Galaxy Cluster'),
            'model' => $modelForForm,
            'fields' => array(
                array(
                    'field' => 'value',
                    'label' => __('Name'),
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
                !isset($origClusterMeta) ? '' : sprintf('<div id="fork_galaxy_preview" class="panel-container fork-cluster-preview"><h5>%s %s</h5>%s</div>',
                    __('Forked Cluster data'),
                    sprintf('<a class="%s %s black" href="%s"></a>', $this->FontAwesome->findNamespace('view'), 'fa-eye', '/galaxy_clusters/view/' . h($origCluster['GalaxyCluster']['id'])),
                    $origClusterHtmlPreview
                ),
                array(
                    'field' => 'galaxy_id',
                    'type' => 'hidden',
                    'default' => $galaxy_id
                ),
                array(
                    'field' => 'forkUuid',
                    'type' => 'hidden',
                    'default' => isset($forkUuid) ? $forkUuid : ''
                ),
                array(
                    'field' => 'forkVersion',
                    'type' => 'hidden',
                    'default' => isset($forkVersion) ? $forkVersion : ''
                ),
                array(
                    'field' => 'description',
                    'type' => 'textarea'
                ),
                array(
                    'field' => 'authors',
                    'rows' => 1,
                    'help' => __('Valid JSON array or comma separated'),
                    'stayInLine' => true
                ),
                array(
                    'field' => 'source'
                ),
                array(
                    'field' => 'elements',
                    'label' => __("Galaxy Cluster Elements"),
                    'type' => 'textarea',
                ),
            ),
            'metaFields' => array(
                $this->element('/GalaxyClusters/clusterElementUI', array('elements' => $this->request->data['GalaxyCluster']['elementsDict']))
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxy_cluster', 'menuItem' => $this->action === 'add' ? 'add' : 'edit'));
?>

<script type="text/javascript">
    var origCluster = <?php echo json_encode($origCluster); ?>;
    $('#GalaxyClusterDistribution').change(function() {
        checkSharingGroup('GalaxyCluster');
    });

    $(document).ready(function() {
        checkSharingGroup('GalaxyCluster');
        $('[data-toggle=\"json\"]').each(function() {
        $(this).attr('data-toggle', '')
            .html(syntaxHighlightJson($(this).text().trim()));
        });
    });
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts