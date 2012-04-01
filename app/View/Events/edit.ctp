<div class="events form">
<?php echo $this->Form->create('Event');?>
	<fieldset>
		<legend><?php echo __('Edit Event'); ?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('date');
		echo $this->Form->input('risk');
		if ('true' == Configure::read('CyDefSIG.sync')) {
		    echo $this->Form->input('private', array(
		            'before' => $this->Html->div('forminfo', 'Prevent upload of this <em>complete Event</em> to other CyDefSIG servers.<br/>Otherwise you can still prevent specific Attributes to be uploaded.'),));
        }
		echo $this->Form->input('info');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit', true));?>
</div>
<div class="actions">
	<ul>

		<li><?php echo $this->Html->link(__('Delete', true), array('action' => 'delete', $this->Form->value('Event.id')), null, sprintf(__('Are you sure you want to delete # %s?', true), $this->Form->value('Event.id'))); ?></li>
		<li>&nbsp;</li>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>