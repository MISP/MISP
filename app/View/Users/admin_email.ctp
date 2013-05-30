<script>
function showMessage(){
	document.getElementById("messageDiv").style.display = "none"){
}
</script>
<div class="events form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Contact User(s)', true); ?></legend>
		<h4>Messaging - here's a quick guide on how this feature works</h4><br />
		You can use this view to send messages to your current or future users or send them a temporary password. <br/> <br />
		<lu><li>When adding a new user to the system, or when you want to manually reset the password for a user, just use the "Send temporary password" setting.</li><br />
		<li>After selecting the action, choose who the target of the e-mails should be (all users, a single user or a user not yet in the system).</li><br />
		<li>You can then specify (if eligible) what the e-mail address of the target is (for existing users you can choose from a dropdown menu).</li><br />
		<li>In the case of a new user, you can specify the future user's gpg key, to send his/her new key in an encrypted e-mail.</li><br />
		<li>The system will automatically generate a message for you, but it is also possible to write a custom message if you tick the check-box,
		but don't worry about assigning a temporary password manually, the system will do that for you, right after your custom message.</li></lu><br />
	<?php
		// This choice will determine
		$actionOptions = array('Custom message', 'Send temporary password');
		$recipientOptions = array('All existing users', 'An existing user', 'New user');
		echo '<div>';
		echo $this->Form->input('action', array('type' => 'select', 'options' => $actionOptions, 'id' => 'action'));
		echo $this->Form->input('recipient', array('type' => 'select', 'options' => $recipientOptions, 'id' => 'recipient'));
		echo '</div>';
		echo '<div id = "recipientEmail">';
		echo $this->Form->input('recipientEmail', array('type' => 'text', 'label' => 'Recipient Email', 'style' => 'width:300px;'));
		echo '</div>';
		echo '<div id = "subject">';
		echo $this->Form->input('subject', array('type' => 'text', 'label' => 'Subject', 'style' => 'width:400px;'));
		echo '</div>';
		echo '<div id = "recipientEmailList">';
		echo $this->Form->input('recipientEmailList', array('type' => 'select', 'options' => $recipientEmail, 'label' => 'Recipient Email'));
		echo '</div>';
		echo '<div id = "gpg">';
		echo $this->Form->input('gpg', array('type' => 'textarea'));
		echo '</div>';
		echo '<div id = "customMessage">';
		echo $this->Form->input('customMessage', array(
				'label' => __('Enter a custom message', true),
				'type' => 'checkbox',
				'checked' => 'checked',
				'id' => 'customMessageToggle'
		));
		echo '</div>';
		$str = $this->Form->input('message', array('type' => 'textarea'));
		echo $this->Html->div('messageDiv', $str, array('id' => 'messageDiv'));
	?>
	<?php echo $this->Form->end(__('Submit', true));
	// link an onchange event to the form elements
	?>
	</fieldset>
</div>
<script>

$("#recipient").change(setRecipientEmailList);
$("#recipient").change(setGPG);
$("#action").change(setMessage);
$("#customMessage").change(setMessage2);
$(document).ready(setRecipientEmailList);
$(document).ready(setGPG);
$(document).ready(setMessage);


function setRecipientEmailList() {
	if ($("#recipient option:selected").text() == "An existing user") {
		document.getElementById("recipientEmailList").style.display = "";
		document.getElementById("recipientEmail").style.display = "none";
	} else if ($("#recipient option:selected").text() == "All existing users") {
		document.getElementById("recipientEmailList").style.display = "none";
		document.getElementById("recipientEmail").style.display = "none";
	} else if ($("#recipient option:selected").text() == "New user") {
		document.getElementById("recipientEmailList").style.display = "none";
		document.getElementById("recipientEmail").style.display = "";
	}
}



function setMessage() {
	if ($("#action option:selected").text() == "Custom message") {
		document.getElementById("customMessage").style.display = "none";
		document.getElementById("messageDiv").style.display = "";
		document.getElementById("subject").style.display = "";
	} else {
		document.getElementById("customMessage").style.display = "";
		document.getElementById("subject").style.display = "none";
		setMessage2();
	}
}

function setMessage2() {
	if ($("#customMessageToggle").prop('checked')) {
		document.getElementById("messageDiv").style.display = "";
	} else {
		document.getElementById("messageDiv").style.display = "none";
	}
}

function setGPG(){
	if ($("#recipient option:selected").text() == "New user") {
		document.getElementById("gpg").style.display = "";
	} else {
		document.getElementById("gpg").style.display = "none";
	}
}
</script>

