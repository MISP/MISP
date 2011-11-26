<div class="signatures form">
<?php echo $this->Form->create('Signature');?>
	<fieldset>
		<legend><?php __('Add Signature'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('type');
		echo $this->Form->input('value', array('error' => array('escape' => false)));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>