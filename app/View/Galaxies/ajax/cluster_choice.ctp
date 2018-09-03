<div class="popover_choice select_cluster">
    <legend><?php echo __('Select Cluster');?></legend>
    <div class="hidden">
        <?php
            echo $this->Form->create('Galaxy', array('url' => '/galaxies/attachCluster/' . $target_type . '/' . $target_id, 'style' => 'margin:0px;'));
            echo $this->Form->input('target_id', array('type' => 'text'));
            echo $this->Form->end();
        ?>
    </div>
    <div style="text-align:right;width:100%;" class="select_tag_search">
        <input id="clusterFilterField" style="width:100%;border:0px;padding:0px;" placeholder="<?php echo __('search clusters…');?>"/>
    </div>
    <div class="popover_choice_main" id ="popover_choice_main">
        <table style="width:100%;">
    <?php
        foreach ($clusters as $namespace => $cluster_data):
            foreach ($cluster_data as $k => $cluster):
                $title = isset($cluster['description']) ? $cluster['description'] : $cluster['value'];
    ?>
                <tr id="field_<?php echo h($cluster['id']); ?>" style="border-bottom:1px solid black;" class="templateChoiceButton filterableButton">
                    <td class="clusterSelectChoice" data-target-type="<?php echo h($target_type); ?>" data-target-id="<?php echo h($target_id); ?>" data-cluster-id="<?php echo h($cluster['id']); ?>" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" title="<?php echo 'Synonyms: ' . h($cluster['synonyms_string']); ?>"><?php echo h($cluster['value']) . ' (' . h($cluster['type']) . ')'; ?></td>
                </tr>
    <?php
            endforeach;
        endforeach;
    ?>
        <tr style="border-bottom:1px solid black;" class="templateChoiceButton">
            <td class="clusterSelectBack" style="padding-left:10px;padding-right:10px; text-align:center;width:100%;" data-target-type="<?php echo h($target_type); ?>" data-event-id="<?php echo h($target_id); ?>" title="Select Galaxy"><?php echo __('Back to Galaxy Selection');?></td>
        </tr>
        </table>
    </div>
    <div role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="templateChoiceButton templateChoiceButtonLast" onClick="cancelPopoverForm();"><?php echo __('Cancel');?></div>
</div>
<script type="text/javascript">
    var lookup_table = <?php echo json_encode($lookup_table); ?>;
    $(document).ready(function() {
        resizePopoverBody();
         $("#clusterFilterField").focus();
    });

    $('.clusterSelectBack').click(function() {
        getPopup($(this).data('target-type') + '/' + $(this).data('target-id'), 'galaxies', 'selectGalaxy');
    });

    $('.clusterSelectChoice').click(function() {
        quickSubmitGalaxyForm($(this).data('target-type') + '/' + $(this).data('target-id'), $(this).data('cluster-id'));
    });
    $('#clusterFilterField').keyup(function() {
        var filterString =  $("#clusterFilterField").val().toLowerCase();
        $('.filterableButton').hide();
        $.each(lookup_table, function(namespace, namespace_data) {
            $.each(namespace_data, function(index, value) {
                var found = false;
                if (index.toLowerCase().indexOf(filterString) != -1) {
                    $.each(value, function(k, v) {
                        $('#field_' + v).show();
                    });
                }
            });
        });
    });
    $(window).resize(function() {
        resizePopoverBody();
    });
</script>
