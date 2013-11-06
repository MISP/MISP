<script>
function showMessage(){
	document.getElementById("messageDiv").style.display="none"){
}
</script>
<div class="events form">
<?php echo $this->Form->create('User');?>
	<fieldset>
		<legend><?php echo __('Contact User(s)', true); ?></legend>
		<h4>Messaging - here's a quick guide on how this feature works</h4>
		You can use this view to send messages to your current or future users or send them a temporary password.
		<ul>
			<li>When adding a new user to the system, or when you want to manually reset the password for a user, just use the "Send temporary password" setting.</li>
			<li>After selecting the action, choose who the target of the e-mails should be (all users, a single user or a user not yet in the system).</li>
			<li>You can then specify (if eligible) what the e-mail address of the target is (for existing users you can choose from a dropdown menu).</li>
			<li>In the case of a new user, you can specify the future user's gpg key, to send his/her new key in an encrypted e-mail.</li>
			<li>The system will automatically generate a message for you, but it is also possible to write a custom message if you tick the check-box,
			but don't worry about assigning a temporary password manually, the system will do that for you, right after your custom message.</li>
		</ul>
		<?php
		// This choice will determine
		$actionOptions=array('Custom message', 'Send temporary password');
		$recipientOptions=array('All existing users', 'An existing user', 'New user');
		?>
		<div class="row-fluid">
			<?php echo $this->Form->input('action', array('type' => 'select', 'options' => $actionOptions, 'id' => 'action')); ?>
			<div id="subject">
				<?php echo $this->Form->input('subject', array('type' => 'text', 'label' => 'Subject', 'style' => 'width:400px;')); ?>
			</div>
		</div>
		<div class="row-fluid">
			<?php echo $this->Form->input('recipient', array('type' => 'select', 'options' => $recipientOptions, 'id' => 'recipient'));	?>
			<div id="recipientEmail">
				<?php echo $this->Form->input('recipientEmail', array('type' => 'text', 'label' => 'Recipient Email', 'style' => 'width:300px;')); ?>
			</div>
			<div id="recipientEmailList">
				<?php echo $this->Form->input('recipientEmailList', array('type' => 'select', 'options' => $recipientEmail, 'label' => 'Recipient Email')); ?>
			</div>
		</div>
		<div id="gpg" class="row-fluid">
			<?php echo $this->Form->input('gpg', array('type' => 'textarea', 'class' => 'input-xxlarge')); ?>
		</div>
		<div id="customMessage" class="row-fluid">
			<?php
			echo $this->Form->input('customMessage', array(
				'label' => __('Enter a custom message', true),
				'type' => 'checkbox',
				'checked' => 'checked',
				'id' => 'customMessageToggle'
			));
			?>
		</div>
		<div class="row-fluid">
			<?php
			$str=$this->Form->input('message', array('type' => 'textarea', 'class' => 'input-xxlarge'));
			echo $this->Html->div('messageDiv', $str, array('id' => 'messageDiv'));
			?>
		</div>
		<div class="row-fluid">
			<?php
			echo $this->Form->button(__('Submit'), array('class' => 'btn btn-primary'));
			echo $this->Form->end();
			?>
		</div>
	</fieldset>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'contact'));
?>
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
		document.getElementById("recipientEmailList").style.display="";
		document.getElementById("recipientEmail").style.display="none";
	} else if ($("#recipient option:selected").text() == "All existing users") {
		document.getElementById("recipientEmailList").style.display="none";
		document.getElementById("recipientEmail").style.display="none";
	} else if ($("#recipient option:selected").text() == "New user") {
		document.getElementById("recipientEmailList").style.display="none";
		document.getElementById("recipientEmail").style.display="";
	}
}



function setMessage() {
	if ($("#action option:selected").text() == "Custom message") {
		document.getElementById("customMessage").style.display="none";
		document.getElementById("messageDiv").style.display="";
		document.getElementById("subject").style.display="";
	} else {
		document.getElementById("customMessage").style.display="";
		document.getElementById("subject").style.display="none";
		setMessage2();
	}
}

function setMessage2() {
	if ($("#customMessageToggle").prop('checked')) {
		document.getElementById("messageDiv").style.display="";
	} else {
		document.getElementById("messageDiv").style.display="none";
	}
}

function setGPG(){
	if ($("#recipient option:selected").text() == "New user") {
		document.getElementById("gpg").style.display="";
	} else {
		document.getElementById("gpg").style.display="none";
	}
}

</script>
