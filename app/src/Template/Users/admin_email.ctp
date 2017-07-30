<div class="events form">
	<h2>Contact User(s)</h2>

<?php echo $this->Form->create('User');?>
	<fieldset>
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
		$actionOptions=array('Custom message', 'Welcome message', 'Reset password');
		$recipientOptions=array('A single user', 'All users');
		?>
		<div class="row-fluid">
			<?php echo $this->Form->input('action', array('type' => 'select', 'options' => $actionOptions, 'id' => 'action')); ?>
			<div id="subject">
				<?php echo $this->Form->input('subject', array('type' => 'text', 'label' => 'Subject', 'style' => 'width:400px;')); ?>
			</div>
		</div>
		<div class="row-fluid">
			<?php echo $this->Form->input('recipient', array('type' => 'select', 'options' => $recipientOptions, 'id' => 'recipient'));	?>
			<div id="recipientEmailList" class="hideAble">
				<?php echo $this->Form->input('recipientEmailList', array('type' => 'select', 'options' => $recipientEmail, 'label' => 'Recipient Email')); ?>
			</div>
		</div>
		<div id="customMessage" class="row-fluid hideAble">
			<?php
			echo $this->Form->input('customMessage', array(
				'label' => __('Enter a custom message', true),
				'type' => 'checkbox',
				'id' => 'customMessageToggle'
			));
			?>
		</div>
		<div class="row-fluid">
			<div id="messageDiv" class="messageDiv hideAble">
				<?php
				echo $this->Form->input('message', array('type' => 'textarea', 'class' => 'input-xxlarge'));
				?>
			</div>
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
$("#recipient").change(setAll);
$("#action").change(setAll);
$("#customMessage").change(setAll);
$("#action").change(populateSubject);
var subjects = [];
var standardTexts = [];
$(document).ready(function() {
	var org = "<?php echo $org;?>";
	subjects = ["", "[" + org + " MISP] New user registration", "[" + org + " MISP] Password reset"];
	standardTexts = ['', '<?php echo h($newUserText); ?>', '<?php echo h($passwordResetText); ?>'];
	//setAll();
});

function populateSubject() {
	$("#UserSubject").val(subjects[$("#action").val()]);
	$("#UserMessage").html(standardTexts[$("#action").val()]).text();
}

function setAll() {
	$(".hideAble").hide();
	if ($("#action option:selected").val() == 0 || $("#customMessageToggle").prop('checked')) $("#messageDiv").show();
	if ($("#action option:selected").val() == 0) $("#subject").show();
	else $("#customMessage").show();
	if ($("#recipient option:selected").val() == 0) $("#recipientEmailList").show();
}


</script>
