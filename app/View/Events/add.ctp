<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Add Event'); ?></legend>
	<?php
		echo $this->Form->input('date');
		echo $this->Form->input('risk');
		echo $this->Form->input('info');
		
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>

	</ul>
</div>