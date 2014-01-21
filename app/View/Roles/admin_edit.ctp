<div class="roles form">
<?php echo $this->Form->create('Role');?>
	<fieldset>
		<legend><?php echo __('Edit Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->input('permission', array('label' => 'Permissions', 'type' => 'select', 'options' => $options), array('value' => '3'));?>
		<div class = 'input clear'></div>

		<?php echo $this->Form->input('perm_sync', array('type' => 'checkbox'));?>
		<?php echo $this->Form->input('perm_admin', array('type' => 'checkbox'));?>
		<?php echo $this->Form->input('perm_audit', array('type' => 'checkbox'));?>
		<?php echo $this->Form->input('perm_auth', array('type' => 'checkbox'));?>
		<?php echo $this->Form->input('perm_site_admin', array('type' => 'checkbox'));?>
		<?php echo $this->Form->input('perm_regexp_access', array('type' => 'checkbox'));?>
		<?php echo $this->Form->input('perm_tagger', array('type' => 'checkbox'));?>
	</fieldset>
<?php
	echo $this->Form->button('Edit', array('class' => 'btn btn-primary'));
	echo $this->Form->end();
?>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'editRole'));

	$this->Js->get('#RolePermission')->event('change', 'deactivateActions()');
	
	$this->Js->get('#RolePermSync')->event('change', 'checkPerms("RolePermSync")');
	$this->Js->get('#RolePermAdmin')->event('change', 'checkPerms("RolePermAdmin")');
	$this->Js->get('#RolePermAudit')->event('change', 'checkPerms("RolePermAudit")');
	$this->Js->get('#RolePermSiteAdmin')->event('change', 'checkPerms("RolePermSiteAdmin");activateAll();');
	$this->Js->get('#RolePermRegexpAccess')->event('change', 'checkPerms("RolePermRegexpAccess")');
	$this->Js->get('#RolePermTagger')->event('change', 'checkPerms("RolePermTagger")');
?>

<script type="text/javascript">
// only be able to tick perm_sync if manage org events and above.

function deactivateActions() {
	var e = document.getElementById("RolePermission");
	if (e.options[e.selectedIndex].value == '0' || e.options[e.selectedIndex].value == '1') {
		document.getElementById("RolePermSync").checked = false;
		document.getElementById("RolePermAdmin").checked = false;
		document.getElementById("RolePermAudit").checked = false;
		document.getElementById("RolePermSiteAdmin").checked = false;
		document.getElementById("RolePermRegexpAccess").checked = false;
		document.getElementById("RolePermRegexpTagger").checked = false;
	}
}

function activateAll() {
	if (document.getElementById("RolePermSiteAdmin").checked) {
		document.getElementById("RolePermSync").checked = true;
		document.getElementById("RolePermAdmin").checked = true;
		document.getElementById("RolePermAudit").checked = true;
		document.getElementById("RolePermAuth").checked = true;
		document.getElementById("RolePermRegexpAccess").checked = true;
		document.getElementById("RolePermTagger").checked = true;
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