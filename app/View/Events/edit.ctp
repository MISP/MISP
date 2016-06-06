<?php
$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Event']['orgc_id'] == $me['org_id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id']));
$mayPublish = ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id']);
?>
<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend>Edit Event</legend>
<?php
	echo $this->Form->input('id');
	echo $this->Form->input('date', array(
			'type' => 'text',
			'class' => 'datepicker'
	));
	echo $this->Form->input('distribution', array(
		'options' => array($distributionLevels),
		'label' => 'Distribution',
		'default' => $event['Event']['distribution'],
	));
?>
	<div id="SGContainer" style="display:none;">
		<?php
		if (!empty($sharingGroups)) {
			echo $this->Form->input('sharing_group_id', array(
				'options' => array($sharingGroups),
				'label' => 'Sharing Group',
				'default' => $event['Event']['sharing_group_id'],
			));
		}
		?>
	</div>
<?php
	echo $this->Form->input('threat_level_id', array(
			'div' => 'input clear'
			));
	echo $this->Form->input('analysis', array(
			'options' => array($analysisLevels),
			));
	echo $this->Form->input('info', array(
			'div' => 'clear',
			'label' => 'Event Info',
			'div' => 'clear',
			'type' => 'text',
			'class' => 'form-control span6',
			'placeholder' => 'Quick Event Description or Tracking Info'
			));

?>
	</fieldset>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
<div id="confirmation_box" class="confirmation_box"></div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'editEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>

<script type="text/javascript">
//
//Generate tooltip information
//
var formInfoValues = {
		'EventDistribution' : new Array(),
		'EventThreatLevelId' : new Array(),
		'EventAnalysis' : new Array()
};

<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventDistribution']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($riskDescriptions as $type => $def) {
	echo "formInfoValues['EventThreatLevelId']['" . addslashes($type) . "'] = \"" . addslashes($def) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($analysisDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventAnalysis']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
?>

$(document).ready(function() {
	if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
	else $('#SGContainer').hide();

	$('#EventDistribution').change(function() {
		if ($('#EventDistribution').val() == 4) $('#SGContainer').show();
		else $('#SGContainer').hide();
	});

	$("#EventAnalysis, #EventThreatLevelId, #EventDistribution").on('mouseover', function(e) {
	    var $e = $(e.target);
	    if ($e.is('option')) {
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'focus',
	            placement: 'right',
	            content: formInfoValues[e.currentTarget.id][$e.val()],
	        }).popover('show');
		}
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#EventAnalysis, #EventThreatLevelId, #EventDistribution").on('change', function(e) {
		var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'focus',
            placement: 'right',
            content: formInfoValues[e.currentTarget.id][$e.val()],
        }).popover('show');
	});
});

</script>
<?php echo $this->Js->writeBuffer();
