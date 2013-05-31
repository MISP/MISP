<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
	<fieldset>
		<legend>Add Import Regexp</legend>
	<?php
		echo $this->Form->input('regexp');
		echo $this->Form->input('replacement');
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Regexp', array('admin' => true, 'action' => 'index'));?></li>
		<li class="active"><?php echo $this->Html->link('New Regexp', array('admin' => true, 'action' => 'add'));?></li>
		<li><?php echo $this->Html->link('Perform on existing', array('admin' => true, 'action' => 'clean'));?></li>
	</ul>
</div>
