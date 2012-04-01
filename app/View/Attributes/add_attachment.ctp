<div class="attributes form">
<?php echo $this->Form->create('Attribute', array('enctype' => 'multipart/form-data'));?>
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
        if ('true' == Configure::read('CyDefSIG.sync')) {
            echo $this->Form->input('private', array(
                    'before' => $this->Html->div('forminfo', 'Prevent upload of this <em>complete Event</em> to other CyDefSIG servers.<br/>Otherwise you can still prevent specific Attributes to be uploaded.'),));
        }
	?>
	</fieldset>
<?php echo $this->Form->end(__('Upload'));?>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
