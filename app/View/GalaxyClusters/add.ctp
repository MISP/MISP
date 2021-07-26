<?php
    $modelForForm = 'GalaxyCluster';
    $forkedCluster = isset($forkedCluster) ? $forkedCluster : array();
    $forkedClusterHtmlPreview = '';
    if (isset($forkedClusterMeta)) {
        foreach ($forkedClusterMeta as $key => $value) {
            if (is_array($value)) {
                $forkedClusterHtmlPreview .= sprintf('<div><b>%s: </b><div data-toggle="json" class="large-left-margin">%s</div></div>', h($key), json_encode(h($value)));
            } else {
                $forkedClusterHtmlPreview .= sprintf('<div><b>%s: </b>%s</div>', h($key), h($value));
            }
        }
    }

    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => (
                $action == 'add' ?
                    (isset($forkedClusterMeta) ? __('Fork Galaxy Cluster') : __('Add Galaxy Cluster')) :
                    __('Edit Galaxy Cluster')
            ),
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
                !isset($forkedClusterMeta) ? '' : sprintf('<div id="fork_galaxy_preview" class="panel-container fork-cluster-preview"><h5>%s %s</h5>%s</div>',
                    __('Forked Cluster data'),
                    sprintf('<a class="%s %s black" href="%s"></a>', $this->FontAwesome->findNamespace('view'), 'fa-eye', '/galaxy_clusters/view/' . h($forkedCluster['GalaxyCluster']['id'])),
                    $forkedClusterHtmlPreview
                ),
                array(
                    'field' => 'galaxy_id',
                    'type' => 'hidden',
                    'default' => $galaxy_id
                ),
                array(
                    'field' => 'extends_uuid',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'extends_version',
                    'type' => 'hidden',
                ),
                array(
                    'field' => 'description',
                    'type' => 'textarea',
                    'class' => 'input span6',
                    'div' => 'input clear'
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
                    'class' => 'input span6',
                    'div' => 'input clear',
                    'picker' => array(
                        'text' => __('Toggle UI'),
                        'function' => 'initClusterElementUI'
                    )
                ),
            ),
            'metaFields' => array(
                $this->element('/GalaxyClusters/clusterElementUI', array(
                    'elements' => isset($this->request->data['GalaxyCluster']['elementsDict']) ? $this->request->data['GalaxyCluster']['elementsDict'] : array(),
                    'drawToggleButton' => false,
                ))
            )
        )
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'galaxies', 'menuItem' => $this->action === 'add' ? 'add_cluster' : 'edit_cluster'));
?>

<script type="text/javascript">
    var forkedCluster = <?php echo json_encode($forkedCluster); ?>;
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
