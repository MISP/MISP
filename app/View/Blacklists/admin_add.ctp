<div class="whitelist form">
<?php echo $this->Form->create('Blacklist');?>
	<fieldset>
		<legend>Add Import Blacklist</legend>
	<?php
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Blacklist', array('admin' => true, 'action' => 'index'));?></li>
		<li class="active"><?php echo $this->Html->link('New Blacklist', array('admin' => true, 'action' => 'add'));?></li>
	</ul>
</div>