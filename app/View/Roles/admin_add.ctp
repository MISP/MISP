<div class="roles form">
<?php echo $this->Form->create('Role');?>
	<fieldset>
		<legend>Add Role</legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->input('permission', array('type' => 'select', 'options' => $options), array('value' => '3'));?>
		<div class = 'input clear'></div>
		<?php echo $this->Form->input('perm_sync', array('type' => 'checkbox', 'checked' => false));?>
		<?php echo $this->Form->input('perm_admin', array('type' => 'checkbox', 'checked' => false));?>
		<?php echo $this->Form->input('perm_audit', array('type' => 'checkbox', 'checked' => false));?>
		<div class = 'input clear'></div>
		<?php echo $this->Form->input('perm_auth', array('type' => 'checkbox', 'checked' => false));?>
		<?php echo $this->Form->input('perm_site_admin', array('type' => 'checkbox', 'checked' => false));?>
		<?php echo $this->Form->input('perm_regexp_access', array('type' => 'checkbox', 'checked' => false));?>
	</fieldset>
<?php
echo $this->Form->button('Add', array('class' => 'btn btn-primary'));
echo $this->Form->end();
?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('New User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
		<li class="divider"></li>
		<?php if ($isSiteAdmin): ?>
		<li class="active"><?php echo $this->Html->link('New Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
		<?php endif; ?>
		<li><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
		<?php if ($isSiteAdmin): ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Contact users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
		<?php endif; ?>
	</ul>
</div>

<?php
$this->Js->get('#RolePermission')->event('change', 'deactivateActions()');

$this->Js->get('#RolePermSync')->event('change', 'checkPerms("RolePermSync")');
$this->Js->get('#RolePermAdmin')->event('change', 'checkPerms("RolePermAdmin")');
$this->Js->get('#RolePermAudit')->event('change', 'checkPerms("RolePermAudit")');
$this->Js->get('#RolePermSiteAdmin')->event('change', 'checkPerms("RolePermSiteAdmin");activateAll();');
$this->Js->get('#RolePermRegexpAccess')->event('change', 'checkPerms("RolePermRegexpAccess")');
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
	}
}

function activateAll() {
	if (document.getElementById("RolePermSiteAdmin").checked) {
		document.getElementById("RolePermSync").checked = true;
		document.getElementById("RolePermAdmin").checked = true;
		document.getElementById("RolePermAudit").checked = true;
		document.getElementById("RolePermAuth").checked = true;
		document.getElementById("RolePermRegexpAccess").checked = true;
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