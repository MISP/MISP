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
				$passwordPopover = '<span class=\"blue bold\">Length</span>: ' . h($length) . '<br />';
				$passwordPopover .= '<span class=\"blue bold\">Complexity</span>: ' . h($complexity);
				echo $this->Form->input('password', array(
					'label' => 'Password <span id = "PasswordPopover" class="icon-info-sign" ></span>'
				));
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
		echo $this->Form->input('gpgkey', array('label' => 'GPG key', 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => 'Paste the user\'s PGP key here or try to retrieve it from the MIT key server by clicking on "Fetch GPG key" below.'));
	?>
		<div class="clear"><span role="button" tabindex="0" aria-label="Fetch the user's PGP key" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;">Fetch GPG key</span></div>
	<?php
		if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => 'SMIME key', 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => 'Paste the user\'s SMIME public key in PEM format here.'));
		echo $this->Form->input('termsaccepted', array('label' => 'Terms accepted'));
		echo $this->Form->input('change_pw', array('type' => 'checkbox', 'label' => 'Change Password'));
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published', 'type' => 'checkbox'));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests', 'type' => 'checkbox'));

		echo $this->Html->link('Reset Auth Key', array('controller' => 'users', 'action' => 'resetauthkey', $currentId));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('disabled', array('label' => 'Disable this user account'));

	?>
	</fieldset>
	<div style="border-bottom: 1px solid #e5e5e5;width:100%;">&nbsp;</div>
	<div class="clear" style="margin-top:10px;">
<?php
	if (Configure::read('Security.require_password_confirmation')) {
		echo $this->Form->input('current_password', array('type' => 'password', 'div' => false, 'class' => 'input password required', 'label' => 'Confirm with your current password'));
	}
?>
	</div>
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
		$('#PasswordPopover').popover("destroy").popover({
			placement: 'right',
			html: 'true',
			trigger: 'hover',
			content: '<?php echo $passwordPopover; ?>'
		});
	});
</script>
