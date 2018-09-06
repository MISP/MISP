<div class="sightings_advanced">
    <div class="popover-legend"><p><?php echo __('Sighting details'); ?></p></div>
    <div style="margin:10px;">
        <span id="sightingsGraphToggle" class="btn btn-primary qet toggle-left sightingsToggle" data-type="graph"><?php echo __('Graph');?></span>
        <span id="sightingsListAllToggle" class="btn btn-inverse qet toggle sightingsToggle" data-type="all"><?php echo __('All');?></span>
        <span id="sightingsListMyToggle" class="btn btn-inverse qet toggle<?php echo $context == 'event' ? '-right' : ''; ?> sightingsToggle" data-type="org"><?php echo __('My org');?></span>
            <?php
                if ($context == 'attribute'):
            ?>
                    <span id="sightingsAddToggle" class="btn btn-inverse qet toggle-right sightingsToggle" data-type="add"><?php echo __('Add sighting');?></span>
            <?php
                endif;
            ?>
    </div>
    <div id="mainContents" style="margin-top:40px;padding:10px;">
        <div id="sightingsData" class="sightingTab"></div>
        <span style="float:right;margin-bottom:10px;" class="btn btn-inverse" id="cancel"><?php echo __('Cancel');?></span>
    </div>
</div>

<script type="text/javascript">
var object_context = "<?php echo h($context);?>";
$(document).ready(function() {
    id = "<?php echo h($id); ?>";
    $('#cancel').click(function() {
        cancelPopoverForm();
    });
    $('#datepicker').datepicker({
        startDate: '-180d',
        endDate: '+1d',
        orientation: 'bottom',
        autoclose: true,
        format: 'yyyy-mm-dd'
    });
    $('#timepicker').timepicker({
        minuteStep: 1,
        showMeridian: false,
        showSeconds: true,
        maxHours: 24
    });
    loadSightingGraph(id, object_context);
});
$('.sightingsToggle').click(function() {
    $('.sightingsToggle').removeClass('btn-primary');
    $('.sightingsToggle').addClass('btn-inverse');
    $(this).removeClass('btn-inverse');
    $(this).addClass('btn-primary');
    var type = $(this).data('type');
    $('.sightingTab').empty();
    if (type == 'graph') {
        loadSightingGraph(id, object_context);
    } else if (type == 'add') {
        $.get( "/sightings/add/" + id, function(data) {
            $("#sightingsData").html(data);
        });
    } else {
        var org = "";
        if (type == 'org') org = "/<?php echo h($me['org_id']);?>"
        $.get( "/sightings/listSightings/" + id + "/" + object_context + org, function(data) {
            $("#sightingsData").html(data);
        });
    }
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
