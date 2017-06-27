<div class="users form">
<?php echo $this->Form->create('User', array('novalidate'=>true));?>
	<fieldset>
		<legend><?php echo __('Admin Add User'); ?></legend>
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
					'empty' => 'Choose organisation',
			));
		}
		$roleOptions = array('label' => 'Role');
		// We need to make sure that the default role is actually available to the admin (for an org admin it might not be)
		if (!empty($default_role_id) && isset($roles[intval($default_role_id)])) {
			$roleOptions['default'] = $default_role_id;
		}
		echo $this->Form->input('role_id', $roleOptions);
		echo $this->Form->input('authkey', array('value' => $authkey, 'readonly' => 'readonly', 'div' => 'input clear'));
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
		<div class="clear"><span  role="button" tabindex="0" aria-label="Fetch the user's PGP key" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;">Fetch GPG key</span></div>
	<?php
		if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => 'SMIME key', 'div' => 'clear', 'class' => 'input-xxlarge', 'placeholder' => 'Paste the user\'s SMIME public key in PEM format here.'));
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published', 'type' => 'checkbox', 'checked' => true));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests', 'type' => 'checkbox', 'checked' => true));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('disabled', array('label' => 'Disable this user account'));
		echo $this->Form->input('notify', array('label' => 'Send credentials automatically', 'type' => 'checkbox', 'checked' => true));
	?>
	</fieldset>
<?php
	echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
	echo $this->Form->end();?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'addUser'));
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
