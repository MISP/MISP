<div class="users form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Change Password'); ?></legend>
	<?php
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
	?>
	</fieldset>
<?php
echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><a href="/users/news">News</a></li>
		<li><a href="/users/view/me">My Profile</a></li>
		<li><a href="/users/memberslist">Members List</a></li>
		<li><a href="/pages/display/doc/general">User Guide</a></li>
		<li><a href="/users/terms">Terms & Conditions</a></li>
	</ul>
</div>