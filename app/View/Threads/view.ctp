<div class="threads view">
	<h3><?php echo h($thread_title); ?></h3>
<?php
	echo $this->element('eventdiscussion');
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'threads', 'menuItem' => 'view'));
?>