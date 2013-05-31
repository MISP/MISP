<div class="whitelist form">
<?php echo $this->Form->create('Blacklist');?>
	<fieldset>
		<legend>Edit Import Blacklist</legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Blacklist', array('admin' => true, 'action' => 'index'));?></li>
		<li><?php echo $this->Html->link('New Blacklist', array('admin' => true, 'action' => 'add'));?></li>
		<li class="divider"></li>
		<li><?php echo $this->Form->postLink(__('Delete Blacklist'), array('admin' => true, 'action' => 'delete', $this->Form->value('Blacklist.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Blacklist.id')));?></li>
	</ul>
</div>