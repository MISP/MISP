<h3>Add Sighting</h3>
<div id="sightingsEventId" class="hidden" data-event-id="<?php echo h($event_id); ?>"></div>
<?php
	echo $this->Form->create('Sighting', array('id', 'url' => '/sightings/add/' . urlencode(h($id)), 'style' => 'margin-bottom:0px;'));
	echo $this->Form->input('type', array(
			'options' => array('Sighting', 'False-positive', 'Expiration'),
			'default' => 0,
			'style' => 'width:230px;margin-right:0px;'
	));
	echo $this->Form->input('source', array(
		'placeholder' => 'honeypot, IDS sensor id, SIEM,...',
		'style' => 'width:447px;',
		'div' => array('style' => 'width:457px !important;')
	));
	echo $this->Form->label('Sighting date');
	echo $this->Form->input('date', array(
			'type' => 'text',
			'id' => 'datepicker',
			'default' => date('Y-m-d'),
			'style' => 'width:110px;',
			'div' => array('style' => 'width:120px !important;'),
			'label' => false
	));
	echo $this->Form->input('time', array(
		'class' => 'input-mini',
		'default' => date('H:i:s'),
		'id' => 'timepicker',
		'style' => 'width:120px;',
		'div' => array('style' => 'width:120px !important;'),
		'label' => false
	));
?>
<span id="submitButton" role="button" tabindex="0" aria-label="Add sighting" title="Add sighting" class="btn btn-primary" onClick="submitPopoverForm('<?php echo h($id);?>', 'addSighting', '<?php echo h($event_id); ?>')">Add</span>
<div class="input clear"></div>
<?php
	echo $this->Form->end();
