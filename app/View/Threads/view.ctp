<div class="threads view">
	<h3><?php
		if (isset($event_id)) {
			echo '<a href="' . $baseurl . '/events/view/' . $event_id . '">' . h($thread_title) . '</a>';
		} else {
			echo h($thread_title);
		}
	?></h3>
<?php
	echo $this->element('eventdiscussion');
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'threads', 'menuItem' => 'view'));
?>
