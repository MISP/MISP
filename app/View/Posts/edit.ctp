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
<?php 
	echo $this->element('side_menu', array('menuList' => 'threads', 'menuItem' => 'edit'));
?>