<div class="server index">
	<h2>Server settings</h2>
	<?php
		echo $this->element('healthElements/tabs');
		if (in_array($tab, array('MISP', 'Security', 'GnuPG', 'misc'))) {
			echo $this->element('healthElements/settings_tab');
		} else if ($tab == 'diagnostics') {
			echo $this->element('healthElements/diagnostics');
		} else {
			echo $this->element('healthElements/overview');
		}
	?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'index'));
?>