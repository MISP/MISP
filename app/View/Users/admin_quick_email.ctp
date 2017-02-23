<div class="events form">
	<h2 style="margin-bottom:0px;">Contact <?php echo h($user['User']['email']); ?></h2>
	<?php
		$encryptionMessage = 'WARNING: This user does not have an encrpytion key set. The security posture of this instance allows for the sending of cleartext e-mails, so this is what will happen if you proceed.';
		$encryptionColour = 'white red-background';
		if ($encryption) {
			$encryptionMessage = $encryption . ' key found for user, the e-mail will be sent encrypted using this key.';
			$encryptionColour = 'white green-background';
		}
	?>
	<div style="width:545px;" class="bold <?php echo $encryptionColour; ?>"><?php echo $encryptionMessage; ?></div>
	<br />
	<?php
		echo $this->Form->create('User');
		echo $this->Form->input('subject', array('type' => 'text', 'label' => 'Subject', 'style' => 'width:400px;'));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->input('body', array('type' => 'textarea', 'class' => 'input-xxlarge'));
	?>
		<div class="clear"></div>
	<?php
		echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
		echo $this->Form->end();
	?>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'contact'));
?>
