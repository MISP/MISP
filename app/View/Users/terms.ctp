<?php echo $this->element('bread_crumbs'); ?>
<div class="users form">
<h2>CyDefSIG Terms and Conditions</h2>
<p>Please add your terms and conditions here</p>
<?php
if (!$termsaccepted) {
	echo $this->Form->create('User');
	echo $this->Form->hidden('termsaccepted', array('default' => '1'));
	echo $this->Form->end(__('Accept Terms', true));
}
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