<div class="users form">
<?php echo $this->Form->create('User', array('novalidate' => true));?>
	<fieldset>
		<legend><?php echo __('Edit My Profile'); ?></legend>
	<?php
		echo $this->Form->input('email');
	?>
		<div class="input clear"></div>
	<?php
		echo $this->Form->input('password');
		echo $this->Form->input('confirm_password', array('type' => 'password', 'div' => array('class' => 'input password required')));
	?>
		<div class="input clear"></div>
	<?php
		echo $this->Form->input('nids_sid');
	?>
		<div class="input clear"></div>
	<?php
		echo $this->Form->input('gpgkey', array('label' => 'GPG key', 'div' => 'clear', 'class' => 'input-xxlarge'));
		?>
			<div class="clear"><span role="button" tabindex="0" aria-label="Fetch PGP key" onClick="lookupPGPKey('UserEmail');" class="btn btn-inverse" style="margin-bottom:10px;">Fetch GPG key</span></div>
		<?php
		if (Configure::read('SMIME.enabled')) echo $this->Form->input('certif_public', array('label' => 'SMIME Public certificate (PEM format)', 'div' => 'clear', 'class' => 'input-xxlarge'));
		echo $this->Form->input('autoalert', array('label' => 'Receive alerts when events are published', 'type' => 'checkbox'));
		echo $this->Form->input('contactalert', array('label' => 'Receive alerts from "contact reporter" requests', 'type' => 'checkbox'));
	?>
	</fieldset>
<?php echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
echo $this->Form->end();?>
</div>
<?php
	$user['User']['id'] = $id;
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'edit', 'user' => $user));
?>
