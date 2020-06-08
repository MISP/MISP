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
                    'name' => __('Default'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'default',
                ),
                array(
                    'name' => __('Galaxy Cluster Target (galaxy :: cluster)'),
                    'sort' => 'TargetCluster.tag_name',
                    'element' => 'cluster_link',
                    'data_path' => 'TargetCluster',
                    'data_path_relation' => 'GalaxyClusterRelation',
                    'url_params_data_paths' => 'TargetCluster.id',
                    'url' => $baseurl . '/galaxy_clusters/view'
                ),
                array(
                    'name' => __('Relationship Type'),
                    'sort' => 'type',
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterRelation.referenced_galaxy_cluster_type',
                ),
                array(
                    'name' => __('Relationship Tag'),
                    'class' => 'short',
                    'data_path' => 'GalaxyClusterRelationTag.{n}.Tag',
                    'element' => 'tags',
                    'elementParams' => array(
                        'searchScope' => 'taxonomy'
                    )
                ),
                array(
                    'name' => __('Distribution'),
                    'sort' => 'distribution',
                    'data_path' => 'GalaxyClusterRelation.distribution',
                    'element' => 'distribution_levels',
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
                            return ($options['me']['org_id'] == $options['cluster']['GalaxyCluster']['org_id']);
                        },
                        'options' => array(
                            'me' => $me,
                            'cluster' => $cluster
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
    <div>
        <div style="padding: 5px; background-color: #f6f6f6; border-bottom: 1px solid #ccc; ">
            <form id="relationsQuickAddForm">
                <div class="input">
                    <label for="RelationshipSource"><?= __('Source UUID') ?></label>
                    <input id="RelationshipSource" name="source_id" type="text" value="<?= h($cluster['GalaxyCluster']['uuid']) ?>" disabled></input>
                </div>
                <div class="input">
                    <label for="RelationshipType"><?= __('Relationship type') ?></label>
                    <select id="RelationshipType" name="referenced_galaxy_cluster_type">
                        <?php foreach ($existingRelations as $relation): ?>
                            <option value="<?= h($relation) ?>"><?= h($relation) ?></option>
                        <?php endforeach; ?>
                        <option value="<?= __('custom') ?>"><?= __('Custom relationship') ?></option>
                        <input id="RelationshipTypeFreetext" type="text"></input>
                    </select>
                </div>
                <div class="input">
                    <label for="RelationshipTarget"><?= __('Target UUID') ?></label>
                    <input id="RelationshipTarget" name="target_id" type="text"></input>
                </div>
                <div class="input">
                    <label for="RelationshipDistribution"><?= __('Distribution') ?></label>
                    <select id="RelationshipDistribution" name="distribution">
                        <?php foreach ($distributionLevels as $k => $distribution): ?>
                            <option value="<?= h($k) ?>" <?= $k == 3 ? 'selected' : ''?>><?= h($distribution) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="input">
                    <label for="RelationshipTags"><?= __('Tags') ?></label>
                    <input id="RelationshipTags" name="tags" type="text"></input>
                </div>
                <div class="clear"></div>
                <button id="buttonAddRelationship" type="button" class="btn btn-primary" style="">
                    <i class="fas fa-plus"></i>
                    Add relationship
                </button>
            </form>
        </div>
    </div>
    <div style="min-height: 600px; position: relative;">
        <?php echo $this->element('GalaxyClusters/view_relation_tree'); ?>
    </div>
</div>
<div id="referencesTable_div" style="position: relative;" class="statistics_attack_matrix hidden">
    <?= $relationTable ?>
</div>
<script>
function toggleClusterRelations() {
    $('#references_div').toggle({
        effect: 'blind',
        duration: 300,
        complete: buildTree
    });
}

function toggleRelationTable() {
    $('#referencesTable_div').toggle({
        effect: 'blind',
        duration: 300,
    });
}

$(document).ready(function() {
    $('#relationsQuickAddForm #RelationshipType').change(function() {
        toggleFreeText();
    });
    toggleFreeText();

    $('#buttonAddRelationship').click(function() {
        submitRelationshipForm();
    })
});


function toggleFreeText() {
    if ($('#relationsQuickAddForm #RelationshipType').val() === 'custom') {
        $('#relationsQuickAddForm #RelationshipTypeFreetext').show();
    } else {
        $('#relationsQuickAddForm #RelationshipTypeFreetext').hide();
    }
}

function submitRelationshipForm() {
    var url = "<?= $baseurl ?>/galaxy_cluster_relations/add/";
    var data = {
        source_id: $('#RelationshipSource').val(),
        target_id: $('#RelationshipTarget').val(),
        type: $('#RelationshipType').val(),
        tags: $('#RelationshipTags').val(),
        distribution: $('#RelationshipDistribution').val(),
        tags: $('#RelationshipTags').val(),
        freetext_relation: $('#RelationshipTypeFreetext').val(),
    };
    if (data.type === 'custom') {
        data.type = data.freetext_relation;
    }
    toggleLoadingButton(true);
    fetchFormDataAjax(url,
        function(formData) {
            $('body').append($('<div id="temp"/>').html(formData));
            $('#temp #GalaxyClusterRelationGalaxyClusterUuid').val(data.source_id);
            $('#temp #GalaxyClusterRelationReferencedGalaxyClusterUuid').val(data.target_id);
            $('#temp #GalaxyClusterRelationReferencedGalaxyClusterType').val(data.type);
            $('#temp #GalaxyClusterRelationDistribution').val(data.distribution);
            $('#temp #GalaxyClusterRelationTags').val(data.tags);
            $.ajax({
                data: $('#GalaxyClusterRelationAddForm').serialize(),
                success:function (data) {
                    $.get("/galaxy_clusters/viewRelations/<?php echo $cluster['GalaxyCluster']['id']; ?>", function(data) {
                        $("#relations_container").html(data);
                        $("#relations_container").show();
                    });
                },
                error:function(jqXHR, textStatus, errorThrown) {
                    showMessage('fail', textStatus + ": " + errorThrown);
                },
                complete:function() {
                    toggleLoadingButton(false);
                    $('#temp').remove();
                },
                type:"post",
                url: $('#GalaxyClusterRelationAddForm').attr('action')
            });
        },
        function() {
            toggleLoadingButton(false);
        }
    )
}

function toggleLoadingButton(loading) {
    if (loading) {
        $('#buttonAddRelationship > i').removeClass('fa-plus').addClass('fa-spinner fa-spin');
    } else {
        $('#buttonAddRelationship > i').removeClass('fa-spinner fa-spin').addClass('fa-plus');
    }
}
</script>