<div class="signatures form">
<?php echo $this->Form->create('Signature', array('enctype' => 'multipart/form-data'));?>
	<fieldset>
			<legend><?php echo __('Add Attachment'); ?></legend>
	<?php
		echo $this->Form->hidden('event_id');
		echo $this->Form->input('category');
		echo $this->Form->file('value', array(
			'error' => array('escape' => false),
		));
        echo $this->Form->input('malware', array(
                'type' => 'checkbox',
                'checked' => false,
                'after' => ' <i>(Every malware sample will be zipped with the password "infected")</i>',
        ));
	?>
	</fieldset>
<?php echo $this->Form->end(__('Upload'));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
