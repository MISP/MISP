<div class="eventBlacklist form">
<?php echo $this->Form->create('EventBlacklist');?>
	<fieldset>
		<legend>Add Event Blacklist Entries</legend>
		<p>Simply paste a list of all the event UUIDs that you wish to block from being entered.</p>
	<?php
		echo $this->Form->input('uuids', array(
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge'
		));
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlacklistsAdd'));
?>
