<div class="roles form">
<?php echo $this->Form->create('Role'); ?>
	<fieldset>
		<legend>Add Role</legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->input('permission', array('type' => 'select', 'options' => $options), array('value' => '3'));?>
		<div class = 'input clear'></div>
		<?php
			$counter = 1;
			foreach ($permFlags as $k => $flag) {
				echo $this->Form->input($k, array('type' => 'checkbox', 'checked' => false));
				if ($counter%3 == 0) echo "<div class = 'input clear'></div>";
				$counter++;
			}
		?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'addRole'));
	$this->Js->get('#RolePermission')->event('change', 'deactivateActions()');
	foreach ($permFlags as $k => $flag) {
		if ($k !== 'perm_site_admin') $this->Js->get('#' . $flag['id'])->event('change', 'checkPerms("' . $flag['id'] . '")');
		else $this->Js->get('#RolePermSiteAdmin')->event('change', 'checkPerms("RolePermSiteAdmin");activateAll();');
	}
?>

<script type="text/javascript">
// only be able to tick perm_sync if manage org events and above.

function deactivateActions() {
	var e = document.getElementById("RolePermission");
	if (e.options[e.selectedIndex].value == '0' || e.options[e.selectedIndex].value == '1') {
		<?php
			foreach ($permFlags as $k => $flag):
		?>
			document.getElementById("<?php echo $flag['id']; ?>").checked = false;
		<?php
			endforeach;
		?>
	}
}

function activateAll() {
	if (document.getElementById("RolePermSiteAdmin").checked) {
		<?php
		foreach ($permFlags as $k => $flag):
			if ($k !== 'perm_site_admin'):
		?>
			document.getElementById("<?php echo $flag['id']; ?>").checked = true;
		<?php
			endif;
		endforeach;
		?>
	}
}

function checkPerms(id) {
	var e = document.getElementById("RolePermission");
	if (e.options[e.selectedIndex].value == '0' || e.options[e.selectedIndex].value == '1') {
		document.getElementById(id).checked = false;
	}
}
</script>
<?php echo $this->Js->writeBuffer();
