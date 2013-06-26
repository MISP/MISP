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
if ('true' == Configure::read('CyDefSIG.sync')) {
	echo $this->Form->input('distribution', array(
		'options' => array($distributionLevels),
		'label' => 'Distribution',
		'selected' => '3',
	));
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
		<li><a href="/logs/event_index/<?php echo $this->request->data['Event']['id'];?>">View Event History</a></li>
		<li class="active"><a href="/events/edit/<?php echo $this->request->data['Event']['id'];?>">Edit Event</a></li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $this->request->data['Event']['id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><a href="/attributes/add/<?php echo $this->request->data['Event']['id'];?>">Add Attribute</a></li>
		<li><a href="/attributes/add_attachment/<?php echo $this->request->data['Event']['id'];?>">Add Attachment</a></li>
		<li><a href="/events/addIOC/<?php echo $this->request->data['Event']['id'];?>">Populate from IOC</a></li>
		<li class="divider"></li>
		<li><a href="/events/contact/<?php echo $this->request->data['Event']['id'];?>">Contact Reporter</a></li>
		<li><a href="/events/xml/download/<?php echo $this->request->data['Event']['id'];?>">Download as XML</a></li>
		<?php if ($this->request->data['Event']['published']): ?>
		<li><a href="/events/downloadOpenIOCEvent/<?php echo $this->request->data['Event']['id'];?>">Download as IOC</a></li>
		<li><a href="/events/csv/download/<?php echo $this->request->data['Event']['id'];?>">Download as CSV</a></li>
		<?php endif; ?>
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
var formInfoValues = {
		'EventDistribution' : new Array(),
		'EventRisk' : new Array(),
		'EventAnalysis' : new Array()
};

<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventDistribution']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($riskDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventRisk']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
}
foreach ($analysisDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['EventAnalysis']['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";	// as we output JS code we need to add slashes
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
	            content: formInfoValues[e.currentTarget.id][$e.val()],
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
            content: formInfoValues[e.currentTarget.id][$e.val()],
        }).popover('show');
	});
});

</script>
<?php echo $this->Js->writeBuffer();