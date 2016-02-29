<div class="feed form">
<?php echo $this->Form->create('Feed');?>
	<fieldset>
		<legend>Edit MISP Feed</legend>
		<p>Edit a MISP feed source.</p>
	<?php
		echo $this->Form->input('name', array(
				'div' => 'input clear',
				'placeholder' => 'Feed name'
		));
		echo $this->Form->input('provider', array(
				'div' => 'input clear',
				'placeholder' => 'Name of the content provider'
		));
		echo $this->Form->input('url', array(
				'div' => 'input clear',
				'placeholder' => 'URL of the feed'
		));
		echo $this->Form->input('pull_rules', array('style' => 'display:none;', 'label' => false, 'div' => false));
	?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'edit'));
?>
