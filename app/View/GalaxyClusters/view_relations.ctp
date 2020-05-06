<button class="btn btn-inverse" onclick="toggleClusterRelations()"><span class="fa fa-eye-slash"> <?php echo __('Toggle Cluster relationships'); ?></span></button>
<div id="references_div" style="position: relative; border: solid 1px;" class="statistics_attack_matrix hidden">
    <?php
        echo $this->element('GalaxyClusters/view_relations');
    ?>
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
</script>
