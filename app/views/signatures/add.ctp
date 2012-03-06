<div class="signatures form">
<?php echo $this->Form->create('Signature');?>
	<fieldset>
		<legend><?php __('Add Signature'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('type');
		echo $this->Form->input('to_ids', array(
    		'checked' => true,
    		'after' => ' <i>Is this signature specific enough to be exported to IDS systems?</i>',
		));
		echo $this->Form->input('value', array(
			'error' => array('escape' => false),
		));
		echo $this->Form->input('batch_import', array(
				    'type' => 'checkbox',
					'after' => ' <i>When selected each line in the value field will be a signature.</i>',
		));
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