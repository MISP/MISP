<div class="users form">
<?php echo $this->Form->create('User', array('novalidate'=>true));?>
	<fieldset>
		<legend><?php echo __('Admin Edit User'); ?></legend>
	<?php
		echo $this->Form->input('email');
	?>
		<div class="clear"></div>
	<?php
		$password = true;
		if (Configure::read('Plugin.CustomAuth_enable')):
			if (Configure::read('Plugin.CustomAuth_required')):
				$password = false;
			else:
				$userType = Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : 'External authentication';
				echo $this->Form->input('external_auth_required', array('type' => 'checkbox', 'label' => $userType . ' user'));
			endif;

	?>
		<div class="clear"></div>
		<div id="externalAuthDiv">
		<?php
			echo $this->Form->input('external_auth_key', array('type' => 'text'));
		?>
		</div>
	<?php
		endif;
	?>
	<div class="clear"></div>
	<div id="passwordDivDiv">
		<?php
			echo $this->Form->input('enable_password', array('type' => 'checkbox', 'label' => 'Set password'));
		?>
		<div id="PasswordDiv">
			<div class="clear"></div>
			<?php
				echo $this->Form->input('password');
				echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
			?>
		</div>
	</div>
	<div class="clear"></div>
	<?php
		if ($isSiteAdmin) {
			echo $this->Form->input('org_id', array(
					'options' => $orgs,
					'label' => 'Organisation',
			));
		}
		echo $this->Form->input('role_id', array('label' => 'Role'));	// TODO ACL, User edit role_id.
		echo $this->Form->input('authkey', array('disabled' => 'disabled', 'label' => 'Authentication key', 'div' => 'input clear'));
		echo $this->Form->input('nids_sid');
	?>
		<div id = "syncServers" class="hidden">
	<?php
			echo $this->Form->input('server_id', array('label' => 'Sync user for', 'div' => 'clear', 'options' => $servers));
	?>
		</div>
	<?php
		echo $this->Form->input('gpgkey', array('label' => 'GPG key', 'div' => 'clear', 'class' => 'input-xxlarge'));
	?>
			<div class="clear"><span onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;">Fetch GPG key</span></div>
	<?php
		if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => 'SMIME Public certificate (PEM format)', 'div' => 'clear', 'class' => 'input-xxlarge'));
		echo $this->Form->input('termsaccepted', array('label' => 'Terms accepted'));
		echo $this->Form->input('change_pw', array('type' => 'checkbox', 'label' => 'Change Password'));
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published'));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests'));

		echo $this->Html->link('Reset Auth Key', array('controller' => 'users', 'action' => 'resetauthkey', $currentId));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('disabled', array('label' => 'Disable this user account'));

	?>
	</fieldset>
<?php
	echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'editUser'));
?>

<script type="text/javascript">
var syncRoles = <?php echo json_encode($syncRoles); ?>;
$(document).ready(function() {
	syncUserSelected();
	$('#UserRoleId').change(function() {
		syncUserSelected();
	});
	checkUserPasswordEnabled();
	checkUserExternalAuth();
	$('#UserEnablePassword').change(function() {
		checkUserPasswordEnabled();
	});
	$('#UserExternalAuthRequired').change(function() {
		checkUserExternalAuth();
	});
});
</script>
