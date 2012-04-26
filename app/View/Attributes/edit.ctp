<div class="attributes form">
<?php echo $this->Form->create('Attribute');?>
	<fieldset>
		<legend><?php echo __('Edit Attribute'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('category');
		if($attachment) {
		    echo $this->Form->hidden('type');
		    echo "<BR>Type: ".$this->Form->value('Attribute.type');
		} else {
    		echo $this->Form->input('type');
		}
		if ('true' == Configure::read('CyDefSIG.sync')) {
		    echo $this->Form->input('private', array(
		            'before' => $this->Html->div('forminfo', 'Prevent upload of this <em>single Attribute</em> to other CyDefSIG servers.<br/>Only use when the Event is NOT set as Private.'),
		    ));
		}
		echo $this->Form->input('to_ids', array(
		    		'before' => $this->Html->div('forminfo', 'Can we make an IDS signature based on this attribute ?'),
		        	'label' => 'IDS Signature?'
		));
		if($attachment) {
		    echo $this->Form->hidden('value');
		    echo "<BR>Value: ".$this->Form->value('Attribute.value');
		} else {
		    echo $this->Form->input('value', array(
		            'type' => 'textarea',
					'error' => array('escape' => false),
		));
		}
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
	    <li><?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Attribute.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Attribute.id'))); ?></li>
	    <li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

