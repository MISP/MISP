<div class="signatures form">
<?php echo $this->Form->create('Signature');?>
	<fieldset>
		<legend><?php echo __('Add Attribute'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category');
		echo $this->Form->input('type');
		echo $this->Form->input('to_ids', array(
		    		'checked' => true,
		    		'after' => ' <i>Can we make an IDS signature based on this attribute ?</i>',
		        	'label' => 'IDS Signature?'
		));
		echo $this->Form->input('value', array(
					'error' => array('escape' => false),
		));
		echo $this->Form->input('batch_import', array(
				    'type' => 'checkbox',
					'after' => ' <i>When selected each line in the value field will be an attribute.</i>',
		));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
    </ul>
</div>
