<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
	<fieldset>
		<legend>Edit Signature Whitelist</legend>
	<?php
		echo $this->Form->input('id');
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Whitelist', array('admin' => true, 'action' => 'index'));?></li>
		<li><?php echo $this->Html->link('New Whitelist', array('admin' => true, 'action' => 'add'));?></li>
		<li class="divider"></li>
		<li><?php echo $this->Form->postLink(__('Delete Whitelist'), array('admin' => true, 'action' => 'delete', $this->Form->value('Whitelist.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Whitelist.id')));?></li>
	</ul>
</div>