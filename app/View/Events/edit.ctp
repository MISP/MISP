<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Edit Event'); ?></legend>
<?php
	echo $this->Form->input('id');
	echo $this->Form->input('date', array(
			'type' => 'text',
			'class' => 'datepicker'
	));
if ('true' == Configure::read('CyDefSIG.sync')) {
    if ('true' == $canEditDist) {
		echo $this->Form->input('distribution', array(
			'label' => 'Distribution',
			'selected' => 'All communities',
		));
    }
}
	echo $this->Form->input('risk', array(
			'div' => 'input clear'
			));
	echo $this->Form->input('analysis', array(
			'options' => array($analysisLevels),
			));
	echo $this->Form->input('info', array(
			'div' => 'clear',
			'class' => 'input-xxlarge'
			));

?>
	</fieldset>
<?php
echo $this->Form->button('Edit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><a href="/events/view/<?php echo $this->request->data['Event']['id'];?>">View Event</a></li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li class="active"><a href="/events/edit/<?php echo $this->request->data['Event']['id'];?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $this->request->data['Event']['id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $this->request->data['Event']['id'];?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $this->request->data['Event']['id'];?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $this->request->data['Event']['id'];?>">Populate from IOC</a></li>
		<?php else:	?>
		<li><a href="/shadow_attributes/add/<?php echo $this->request->data['Event']['id'];?>">Propose Attribute</a></li>
		<li><a href="/shadow_attributes/add_attachment/<?php echo $this->request->data['Event']['id'];?>">Propose Attachment</a></li>
		<?php endif; ?>
		<li class="divider"></li>
		<?php if ( 0 == $this->request->data['Event']['published'] && ($isAdmin || $mayPublish)): ?>
		<li><?php echo $this->Form->postLink('Publish Event', array('action' => 'alert', $this->request->data['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?'); ?></li>
		<li><?php echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $this->request->data['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!'); ?></li>
		<?php else: ?>
		<!-- ul><li>Alert already sent</li></ul -->
		<?php endif; ?>
		<li><a href="/events/contact/<?php echo $this->request->data['Event']['id'];?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $this->request->data['Event']['id'];?>">Download as XML</a></li>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $this->request->data['Event']['id'];?>">Download as IOC</a></li>
		<li class="divider"></li>
		<li><a href="/events/index">List Events</a></li>
		<?php if ($isAclAdd): ?>
		<li><a href="/events/add">Add Event</a></li>
		<?php endif; ?>
	</ul>
</div>


<script type="text/javascript">
//
//Generate tooltip information
//
var formInfoValues = new Array();
<?php
if ('true' == $canEditDist) {
	foreach ($distributionDescriptions as $type => $def) {
		$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
		echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
	}
}

foreach ($riskDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
foreach ($analysisDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
}
?>

$(document).ready(function() {

	$("#EventAnalysis, #EventRisk, #EventDistribution").on('mouseleave', function(e) {
	    $('#'+e.currentTarget.id).popover('destroy');
	});

	$("#EventAnalysis, #EventRisk, #EventDistribution").on('mouseover', function(e) {
	    var $e = $(e.target);
	    if ($e.is('option')) {
	        $('#'+e.currentTarget.id).popover('destroy');
	        $('#'+e.currentTarget.id).popover({
	            trigger: 'manual',
	            placement: 'right',
	            content: formInfoValues[$e.val()],
	        }).popover('show');
	    }
	});

	// workaround for browsers like IE and Chrome that do now have an onmouseover on the 'options' of a select.
	// disadvangate is that user needs to click on the item to see the tooltip.
	// no solutions exist, except to generate the select completely using html.
	$("#EventAnalysis, #EventRisk, #EventDistribution").on('change', function(e) {
		var $e = $(e.target);
        $('#'+e.currentTarget.id).popover('destroy');
        $('#'+e.currentTarget.id).popover({
            trigger: 'manual',
            placement: 'right',
            content: formInfoValues[$e.val()],
        }).popover('show');
	});
});

</script>
<?php echo $this->Js->writeBuffer();