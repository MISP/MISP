<div class="groups form">
<?php echo $this->Form->create('Group');?>
	<fieldset>
		<legend><?php echo __('Edit Role'); ?></legend>
	<?php
		echo $this->Form->input('name');?>
		<?php echo $this->Form->radio('permission', $options, array('label' => 'Permissions'));?>
		<?php echo $this->Form->input('perm_sync', array('type' => 'checkbox', 'label' => 'Sync Actions'));?>
		<?php echo $this->Form->input('perm_admin', array('type' => 'checkbox', 'label' => 'Administration Actions'));?>
		<?php echo $this->Form->input('perm_audit', array('type' => 'checkbox', 'label' => 'Audit Actions'));?>
	</fieldset>
<?php echo $this->Form->end(__('Submit'));?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

<?php
$this->Js->get('#GroupPermission0')->event('change', 'deactivateActions()');
$this->Js->get('#GroupPermission1')->event('change', 'deactivateActions()');

$this->Js->get('#GroupPermSync')->event('change', 'checkPerms("GroupPermSync")');
$this->Js->get('#GroupPermAdmin')->event('change', 'checkPerms("GroupPermAdmin")');
$this->Js->get('#GroupPermAudit')->event('change', 'checkPerms("GroupPermAudit")');
?>

<script type="text/javascript">
// only be able to tick perm_sync if manage org events and above.

function deactivateActions() {
	document.getElementById("GroupPermSync").checked = false;
	document.getElementById("GroupPermAdmin").checked = false;
	document.getElementById("GroupPermAudit").checked = false;
}

function checkPerms(id) {
	if ((document.getElementById("GroupPermission0").checked) || (document.getElementById("GroupPermission1").checked)) {
		document.getElementById(id).checked = false;
	}
}

</script>
<?php echo $this->Js->writeBuffer();