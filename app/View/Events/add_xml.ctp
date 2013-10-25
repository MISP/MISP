<div class="events form">
<?php echo $this->Form->create('Event', array('type' => 'file'));?>
	<fieldset>
		<legend><?php echo __('Import from MISP XML'); ?></legend>
<?php
	echo $this->Form->input('Event.submittedxml', array(
			'label' => '<b>MISP XML</b>',
			'type' => 'file',
	));
?>
	</fieldset>
<?php
	echo $this->Form->button('Upload', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addXML'));
?>
