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
			foreach ($permFlags as $k => $flag):
		?>
				<div class="permFlags<?php echo ' ' . ($flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled'); ?>">
		<?php
					echo $this->Form->input($k, array('type' => 'checkbox', 'class' => 'checkbox ' . ($flag['readonlyenabled'] ? 'readonlyenabled' : 'readonlydisabled'), 'checked' => false));
					if ($counter%3 == 0) echo "<div class = 'input clear'></div>";
					$counter++;
		?>
				</div>
		<?php
			endforeach;
		?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'addRole'));
<<<<<<< HEAD
=======
	$this->Js->get('#RolePermission')->event('change', 'deactivateActions()');
	foreach ($permFlags as $k => $flag) {
		if ($k == 'perm_audit' || $k == 'perm_auth') {
			continue;
		}
		if ($k !== 'perm_site_admin') $this->Js->get('#' . $flag['id'])->event('change', 'checkPerms("' . $flag['id'] . '")');
		else $this->Js->get('#RolePermSiteAdmin')->event('change', 'checkPerms("RolePermSiteAdmin");activateAll();');
	}
>>>>>>> 2.4
?>

<script type="text/javascript">
	$(document).ready(function() {
		checkRolePerms();
		$(".checkbox, #RolePermission").change(function() {
	  	checkRolePerms();
		});
	});
</script>
<?php echo $this->Js->writeBuffer();
