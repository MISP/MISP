<div class="posts form">
<?php echo $this->Form->create('Post');?>
	<fieldset>
		<legend>Edit Post</legend>
	<?php
		echo $this->Form->input('title', array(
				'label' => 'Thread Subject',
				'class' => 'input-xxlarge',
				'disabled' => 'true',
				'default' => $title
		));
		echo $this->Form->input('contents', array(
				'type' => 'textarea',
				'div' => 'input clear',
				'class' => 'input-xxlarge',
				'default' => $contents
		));
	?>
	</fieldset>
<?php
echo $this->Form->button('Submit', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('Edit Post', array('controller' => 'threads', 'action' => 'view', $id));?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Threads', array('controller' => 'threads', 'action' => 'index'));?></li>
		<li><a href = "<?php echo Configure::read('CyDefSIG.baseurl');?>/posts/add">New Thread</a></li>
	</ul>
</div>