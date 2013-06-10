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
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link(__('News', true), array('controller' => 'users', 'action' => 'news')); ?> </li>
		<li><?php echo $this->Html->link(__('My Profile', true), array('controller' => 'users', 'action' => 'view', 'me')); ?> </li>
		<li><?php echo $this->Html->link(__('Members List', true), array('controller' => 'users', 'action' => 'memberslist')); ?> </li>
		<li><?php echo $this->Html->link(__('User Guide', true), array('controller' => 'pages', 'action' => 'display', 'documentation')); ?> </li>
		<li class="active"><?php echo $this->Html->link(__('Terms & Conditions', true), array('controller' => 'users', 'action' => 'terms')); ?> </li>
	</ul>
</div>