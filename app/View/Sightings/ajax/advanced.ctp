<div class="sightings_advanced">
		<div class="popover-legend"><p><?php echo __('Sighting details'); ?></p></div>
    <div style="margin:10px;">
        <span id="sightingsGraphToggle" class="btn btn-primary qet toggle-left sightingsToggle" data-type="graph">Graph</span>
        <span id="sightingsListAllToggle" class="btn btn-inverse qet toggle sightingsToggle" data-type="all">All</span>
        <span id="sightingsListMyToggle" class="btn btn-inverse qet toggle sightingsToggle" data-type="org">My org</span>
        <span id="sightingsAddToggle" class="btn btn-inverse qet toggle-right sightingsToggle" data-type="add">Add sighting</span>
      </div>
      <div id="mainContents" style="margin-top:40px;padding:10px;">
        <div id="sightingsData" class="sightingTab"></div>
        <span style="float:right;margin-bottom:10px;" class="btn btn-inverse" id="cancel">Cancel</span>
      </div>
 </div>
</div>

<script type="text/javascript">
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
  loadSightingGraph(id, "attribute");
});
$('.sightingsToggle').click(function() {
  $('.sightingsToggle').removeClass('btn-primary');
  $('.sightingsToggle').addClass('btn-inverse');
  $(this).removeClass('btn-inverse');
  $(this).addClass('btn-primary');
  var type = $(this).data('type');
  $('.sightingTab').empty();
  if (type == 'graph') {
    loadSightingGraph(id, "attribute");
  } else if (type == 'add') {
    $.get( "/sightings/add/" + id, function(data) {
      $("#sightingsData").html(data);
    });
  } else {
    var org = "";
    if (type == 'org') org = "/<?php echo h($me['org_id']);?>"
    $.get( "/sightings/listSightings/" + id + "/attribute" + org, function(data) {
      $("#sightingsData").html(data);
    });
  }
});
</script>
<?php echo $this->Js->writeBuffer(); // Write cached scripts
