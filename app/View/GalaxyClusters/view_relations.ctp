<?php
    $relationTable = $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'skip_pagination' => true,
            'data' => $relations,
            'fields' => array(
                array(
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterRelation.id',
                ),
                array(
                    'name' => __('Owner Org'),
                    'class' => 'short',
                    'element' => 'org',
                    'data_path' => 'Org',
                    'fields' => array(
                        'allow_picture' => true,
                        'default_org' => 'MISP'
                    ),
                    'requirement' => $isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))
                ),
                array(
                    'name' => __('Creator Org'),
                    'class' => 'short',
                    'element' => 'org',
                    'data_path' => 'Orgc',
                    'fields' => array(
                        'allow_picture' => true,
                        'default_org' => 'MISP'
                    ),
                    'requirement' => (Configure::read('MISP.showorg') || $isAdmin) || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))
                ),
                array(
                    'name' => __('Default'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'default',
                ),
                array(
                    'name' => __('Galaxy Cluster Target'),
                    'sort' => 'ReferencedGalaxyCluster.tag_name',
                    'element' => 'links',
                    'data_path' => 'ReferencedGalaxyCluster.tag_name',
                    'url_params_data_paths' => 'ReferencedGalaxyCluster.id',
                    'url' => $baseurl . '/galaxy_clusters/view'
                ),
                array(
                    'name' => __('Relationship Type'),
                    'sort' => 'type',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterRelation.referenced_galaxy_cluster_type',
                ),
                // array(
                //     'name' => __('Relationship Tag'),
                //     'class' => 'short',
                //     'data_path' => 'Tag',
                //     'element' => 'GalaxyClusterRelationTag'
                // ),
                array(
                    'name' => __('Distribution'),
                    'sort' => 'distribution',
                    'data_path' => 'GalaxyClusterRelation.distribution',
                    'element' => 'distribution_levels'
                ),
            ),
            'title' => __('Galaxy Cluster Relationships'),
            'actions' => array(
                array(
                    'title' => 'Edit',
                    'url' => '/galaxy_cluster_relations/edit',
                    'url_params_data_paths' => array(
                        'GalaxyClusterRelation.id'
                    ),
                    'icon' => 'edit',
                    'complex_requirement' => array(
                        'function' => function($row, $options) {
                            return ($options['me']['org_id'] == $options['datapath']['org']);
                        },
                        'options' => array(
                            'me' => $me,
                            'datapath' => array(
                                'org' => 'GalaxyClusterRelation.org_id'
                            )
                        )
                    ),
                ),
                array(
                    'title' => 'Delete',
                    'url' => '/galaxy_cluster_relations/delete',
                    'url_params_data_paths' => array(
                        'GalaxyClusterRelation.id'
                    ),
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you want to delete the Relationship?'),
                    'icon' => 'trash'
                ),
            )
        )
    ));
?>

<form class="form-inline">
    <button type="button" class="btn btn-inverse" onclick="toggleClusterRelations()"><span class="fa fa-eye-slash"> <?php echo __('Toggle Cluster relationships'); ?></span></button>
    <label class="checkbox">
        <input type="checkbox" onclick="toggleRelationTable()"> <?= __('Show relation table') ?>
    </label>
</form>

</div>
<div id="references_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix hidden">
    <?php echo $this->element('GalaxyClusters/view_relations'); ?>
</div>
<div id="referencesTable_div" style="position: relative;" class="statistics_attack_matrix hidden">
    <?= $relationTable ?>
</div>
<script>
function toggleClusterRelations() {
    $('#references_div').toggle({
        effect: 'blind',
        duration: 300,
        complete: function() {
            if (window.buildTree !== undefined) {
                buildTree();
            }
        }
    });
}

function toggleRelationTable() {
    $('#referencesTable_div').toggle({
        effect: 'blind',
        duration: 300,
    });
}
</script>