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
	echo $this->Form->input('distribution', array(
		'label' => 'Distribution',
		'selected' => 'All communities',
		'after' => $this->Html->div('forminfo', '', array('id' => 'EventDistributionDiv')),
	));
}
	echo $this->Form->input('risk', array(
			'after' => $this->Html->div('forminfo', '', array('id' => 'EventRiskDiv')),
			'div' => 'input clear'
			));
	echo $this->Form->input('analysis', array(
			'options' => array($analysisLevels),
			'after' => $this->Html->div('forminfo', '', array('id' => 'EventAnalysisDiv'))
			));
	echo $this->Form->input('info', array(
			'div' => 'clear',
			'class' => 'input-xxlarge'
			));

// link an onchange event to the form elements
$this->Js->get('#EventDistribution')->event('change', 'showFormInfo("#EventDistribution")');
$this->Js->get('#EventRisk')->event('change', 'showFormInfo("#EventRisk")');
$this->Js->get('#EventAnalysis')->event('change', 'showFormInfo("#EventAnalysis")');
?>
	</fieldset>
<?php
echo $this->Form->button('Edit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('View Event', array('action' => 'view', $this->request->data['Event']['id'])); ?> </li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li class="active"><?php echo $this->Html->link('Edit Event', array('action' => 'edit', $this->request->data['Event']['id'])); ?> </li>
		<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $this->request->data['Event']['id']), null, __('Are you sure you want to delete # %s?', $this->request->data['Event']['id'])); ?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $this->request->data['Event']['id']));?> </li>
		<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $this->request->data['Event']['id']));?> </li>
		<li><?php echo $this->Html->link('Populate event from IOC', array('controller' => 'events', 'action' => 'addIOC', $this->request->data['Event']['id']));?> </li>
		<?php else:	?>
		<li><?php echo $this->Html->link('Propose Attribute', array('controller' => 'shadow_attributes', 'action' => 'add', $this->request->data['Event']['id']));?> </li>
		<li><?php echo $this->Html->link('Propose Attachment', array('controller' => 'shadow_attributes', 'action' => 'add_attachment', $this->request->data['Event']['id']));?> </li>
		<?php endif; ?>
		<li class="divider"></li>
		<?php if ( 0 == $this->request->data['Event']['published'] && ($isAdmin || $mayPublish)): ?>
		<li><?php echo $this->Form->postLink('Publish Event', array('action' => 'alert', $this->request->data['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?'); ?></li>
		<li><?php echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $this->request->data['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!'); ?></li>
		<?php elseif (0 == $this->request->data['Event']['published']): ?>
		<li>Not published</li>
		<?php else: ?>
		<!-- ul><li>Alert already sent</li></ul -->
		<?php endif; ?>
		<li><?php echo $this->Html->link(__('Contact reporter', true), array('action' => 'contact', $this->request->data['Event']['id'])); ?> </li>
		<li><?php echo $this->Html->link(__('Download as XML', true), array('action' => 'xml', 'download', $this->request->data['Event']['id'])); ?></li>
		<li><?php echo $this->Html->link(__('Download as IOC', true), array('action' => 'downloadOpenIOCEvent', $this->request->data['Event']['id'])); ?> </li>

		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
	</ul>
</div>

<script type="text/javascript">
//
//Generate tooltip information
//
var formInfoValues = new Array();
<?php
foreach ($distributionDescriptions as $type => $def) {
	$info = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
	echo "formInfoValues['" . addslashes($type) . "'] = \"" . addslashes($info) . "\";\n";  // as we output JS code we need to add slashes
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

function showFormInfo(id) {
	idDiv = id+'Div';
	// LATER use nice animations
	//$(idDiv).hide('fast');
	// change the content
	var value = $(id).val();    // get the selected value
	$(idDiv).html(formInfoValues[value]);    // search in a lookup table
	// show it again
	$(idDiv).fadeIn('slow');
}

// hide the formInfo things
$('#EventDistributionDiv').hide();
$('#EventRiskDiv').hide();
$('#EventAnalysisDiv').hide();
</script>
<?php echo $this->Js->writeBuffer();