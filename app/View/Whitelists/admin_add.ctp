<?php echo $this->element('bread_crumbs');?>
<div class="whitelist form">
<?php echo $this->Form->create('Whitelist');?>
	<fieldset>
		<legend>Add Signature Whitelist</legend>
	<?php
		echo $this->Form->input('name');
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Whitelist', array('admin' => true, 'action' => 'index'));?></li>
		<li class="active"><?php echo $this->Html->link('New Whitelist', array('admin' => true, 'action' => 'add'));?></li>
	</ul>
</div>