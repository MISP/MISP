<div class="events form">
	<h2>Contact <?php echo h($user['User']['email']); ?></h2>
	<?php
		echo $this->Form->create('User');
		echo $this->Form->input('subject', array('type' => 'text', 'label' => 'Subject', 'style' => 'width:400px;'));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('body', array('type' => 'textarea', 'class' => 'input-xxlarge'));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
		echo $this->Form->end();
	?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'contact'));
?>
