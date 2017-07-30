<div class="index">
	<h3>GPG key validation</h3>
	<ul>
	<?php foreach ($users as $k => $user) {
		echo '<a href="'.$baseurl.'/admin/users/view/' . $k . '">' . $k . ' (' . h($user[1]) . ')</a>:';
		if (isset($user[0])) {
			echo '-> <span style="color:red;"><span style="font-weight:bold">Invalid.</span> (' . h($user[2]) . ')</span><br />';
		} else {
			echo '-> <span style="color:green;">OK</span><br />';
		}
		echo '------------------------------------------------------------------------------<br />';
	}
	?>
	</ul>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'adminTools'));
?>
