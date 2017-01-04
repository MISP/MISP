<div class="confirmation">
<?php
	$legend = ($firstTime ? 'Send welcome message to user' : 'Initiate password reset for user');
	$message = ($firstTime ? 'Are you sure you want to reset the password of ' . $user['User']['email'] . ' and send him/her a welcome message with the credentials?' : 'Are you sure you want to reset the password of ' . $user['User']['email'] . ' and send him/her the temporary credentials? ');
	echo $this->Form->create('User', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend><?php echo $legend; ?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
	<p><?php echo $message; ?><br />
	<?php echo $this->Form->input('firstTime', array('label' => false, 'type' => 'checkbox', 'div' => false, 'style' => 'border:0px;margin:0px;')); ?>First time registration
	</p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span id="PromptYesButton" class="btn btn-primary" onClick="submitPasswordReset('<?php echo $user['User']['id']; ?>');">Yes</span>
			</td>
			<td style="width:540px;">
			</td>
			<td style="vertical-align:top;">
				<span class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
			</td>
		</tr>
	</table>
</div>
<?php
	echo $this->Form->end();
?>
</div>
