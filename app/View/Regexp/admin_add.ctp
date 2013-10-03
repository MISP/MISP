<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
	<fieldset>
		<legend>Add Import Regexp</legend>
	<?php
		echo $this->Form->input('regexp');
		echo $this->Form->input('replacement');
	?>
	<div class = "clear">
			Types to be affected by the filter (Setting 'all' will override the other settings)
	</div>
				<br />
	<div class="input clear">
	<?php
		echo $this->Form->input('all', array(
			'checked' => false,
			'label' => 'All',
		));
	?>
	</div>
	<div class="input clear">	</div>
	<?php
		foreach($types as $key => $type) {
			echo $this->Form->input($key, array(
				'checked' => false,
				'label' => $type,
			));
		}
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Regexp', array('admin' => true, 'action' => 'index'));?></li>
		<li class="active"><?php echo $this->Html->link('New Regexp', array('admin' => true, 'action' => 'add'));?></li>
		<?php if ($isSiteAdmin) {?>
			<li><?php echo $this->Html->link('Perform on existing', array('admin' => true, 'action' => 'clean'));?></li>
		<?php }?>
	</ul>
</div>
