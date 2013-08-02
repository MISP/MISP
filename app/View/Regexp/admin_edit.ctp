<div class="regexp form">
<?php echo $this->Form->create('Regexp');?>
	<fieldset>
		<legend>Edit Import Regexp</legend>
	<?php
		echo $this->Form->input('id');
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
			'checked' => $all,
			'label' => 'All',
		));
	?>
	</div>
	<div class="input clear">	</div>
	<?php
		if ($all) {
			foreach($types as $key => $type) {
				echo $this->Form->input($key, array(
				'checked' => $value[$key],
				'label' => $type,
				));
			}
		} else {
			foreach($types as $key => $type) {
				echo $this->Form->input($key, array(
					'checked' => $value[$key],
					'label' => $type,
				));
			}
		}
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions">
	<ul>

	</ul>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('List Regexp', array('admin' => true, 'action' => 'index'));?></li>
		<li><?php echo $this->Html->link('New Regexp', array('admin' => true, 'action' => 'add'));?></li>
		<li><?php echo $this->Html->link('Perform on existing', array('admin' => true, 'action' => 'clean'));?></li>
		<li class="divider"></li>
		<li><?php echo $this->Form->postLink('Delete Regexp', array('admin' => true, 'action' => 'delete', $this->Form->value('Regexp.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Regexp.id')));?></li>
	</ul>
</div>
