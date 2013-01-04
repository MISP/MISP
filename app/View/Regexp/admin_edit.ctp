<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
	<fieldset>
		<legend><?php echo __('Edit Import Regexp');?></legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('regexp');
		echo $this->Form->input('replacement');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Form->postLink(__('Delete Whitelist'), array('admin' => true, 'action' => 'delete', $this->Form->value('Whitelist.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Whitelist.id')));?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu');?>
	</ul>
</div>