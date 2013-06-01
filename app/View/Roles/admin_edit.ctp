<div class="roles form">
<?php echo $this->Form->create('Role');?>
	<fieldset>
		<legend><?php echo __('Edit Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->radio('permission', $options, array('label' => 'Permissions', 'style' => 'vertical-align: middle'));?>
		<?php echo $this->Form->input('perm_sync', array('type' => 'checkbox', 'label' => 'Sync Actions', 'style' => 'vertical-align: middle'));?>
		<?php echo $this->Form->input('perm_admin', array('type' => 'checkbox', 'label' => 'Administration Actions', 'style' => 'vertical-align: middle'));?>
		<?php echo $this->Form->input('perm_audit', array('type' => 'checkbox', 'label' => 'Audit Actions', 'style' => 'vertical-align: middle'));?>
		<?php echo $this->Form->input('perm_auth', array('type' => 'checkbox', 'label' => 'Auth Key Access', 'style' => 'vertical-align: middle'));?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('New User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
		<li class="divider"></li>
		<?php if ($isSiteAdmin): ?>
		<li><?php echo $this->Html->link('New Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
		<?php endif; ?>
		<li><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
		<?php if ($isSiteAdmin): ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Contact users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
		<?php endif; ?>
	</ul>
</div>

<?php
$this->Js->get('#RolePermission0')->event('change', 'deactivateActions()');
$this->Js->get('#RolePermission1')->event('change', 'deactivateActions()');

$this->Js->get('#RolePermSync')->event('change', 'checkPerms("RolePermSync")');
$this->Js->get('#RolePermAdmin')->event('change', 'checkPerms("RolePermAdmin")');
$this->Js->get('#RolePermAudit')->event('change', 'checkPerms("RolePermAudit")');
?>

<script type="text/javascript">
// only be able to tick perm_sync if manage org events and above.

function deactivateActions() {
	document.getElementById("RolePermSync").checked = false;
	document.getElementById("RolePermAdmin").checked = false;
	document.getElementById("RolePermAudit").checked = false;
}

function checkPerms(id) {
	if ((document.getElementById("RolePermission0").checked) || (document.getElementById("RolePermission1").checked)) {
		document.getElementById(id).checked = false;
	}
}

</script>
<?php echo $this->Js->writeBuffer();