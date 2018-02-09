<div class="events form">
<?php
  echo $this->Form->create('Event', array('type' => 'file'));
  $stixVersion = 'STIX 1.1.1 XML';
?>
	<fieldset>
		<legend><?php echo __('Import %s file', $stixVersion); ?></legend>
<?php
	echo $this->Form->input('Event.stix', array(
			'label' => '<b>' . __('%s file', $stixVersion) . '</b>',
			'type' => 'file',
	));
	?>
		<div class="input clear"></div>
	<?php
	echo $this->Form->input('publish', array(
			'checked' => false,
			'label' => __('Publish imported events'),
	));
?>
	</fieldset>
<?php
	echo $this->Form->button(__('Upload'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'addSTIX'));
?>
