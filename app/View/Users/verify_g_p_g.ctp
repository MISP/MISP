<div class="index">
	<h3>GPG key validation</h3>
	<ul>
	<?php foreach ($users as $k => $user) { 
		echo $k . ' (' . $user[1] . '):<br />';
		if ($user[0]) {
			echo '-> PGP key invalid.<br />';
		}
		echo '------------------------------------------------------------------------------<br />';
	}
	 ?>
	 </ul>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>