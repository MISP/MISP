<div class="events form">
    <h2><?php echo __('Contact User(s)');?></h2>

<?php echo $this->Form->create('User');?>
    <fieldset>
        <h4><?php echo __('Messaging - here\'s a quick guide on how this feature works');?></h4>
        <?php echo __('You can use this view to send messages to your current or future users or send them a temporary password.');?>
        <ul>
            <li><?php echo __('When adding a new user to the system, or when you want to manually reset the password for a user, just use the "Send temporary password" setting.');?></li>
            <li><?php echo __('After selecting the action, choose who the target of the e-mails should be (all users, a single user or a user not yet in the system).');?></li>
            <li><?php echo __('You can then specify (if eligible) what the e-mail address of the target is (for existing users you can choose from a dropdown menu).');?></li>
            <li><?php echo __('In the case of a new user, you can specify the future user\'s PGP key, to send his/her new key in an encrypted e-mail.');?></li>
            <li><?php echo __('The system will automatically generate a message for you, but it is also possible to write a custom message if you tick the check-box,
                        but don\'t worry about assigning a temporary password manually, the system will do that for you, right after your custom message.');?></li>
        </ul>
        <?php
        // This choice will determine
        $actionOptions=array(__('Custom message'), __('Welcome message'), __('Reset password'));
        $recipientOptions=array(__('A single user'),  __('All users'), __('All users of the same organisation'));
        ?>
        <div class="row-fluid">
            <?php echo $this->Form->input('action', array('type' => 'select', 'options' => $actionOptions, 'id' => 'action')); ?>
            <div id="subject">
                <?php echo $this->Form->input('subject', array('type' => 'text', 'label' => __('Subject'), 'style' => 'width:400px;')); ?>
            </div>
        </div>
        <div class="row-fluid">
            <?php echo $this->Form->input('recipient', array('type' => 'select', 'options' => $recipientOptions, 'id' => 'recipient')); ?>
            <div id="recipientEmailList" class="hideAble">
                <?php echo $this->Form->input('recipientEmailList', array('type' => 'select', 'options' => $recipientEmail, 'label' => __('Recipient Email'))); ?>
            </div>
            <div id="orgNameList" class="hideAble">
                <?php echo $this->Form->input('orgNameList', array('type' => 'select', 'options' => $orgName, 'label' => __('Recipient Organisation Name'))); ?>
            </div>
        </div>
        <div id="customMessage" class="row-fluid hideAble">
            <?php
            echo $this->Form->input('customMessage', array(
                'label' => __('Enter a custom message'),
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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'contact'));
?>
<script>
$("#recipient").change(setAll);
$("#action").change(setAll);
$("#customMessage").change(setAll);
$("#action").change(populateSubject);
var subjects = [];
var standardTexts = [];
var submitAllowed = false;
$(document).ready(function() {
    var org = "<?php echo $org;?>";
    subjects = ["", "[" + org + " MISP] " + "<?php echo __('New user registration');?>" , "[" + org + " MISP] " + "<?php echo __('Password reset');?>"];
    standardTexts = ['', '<?php echo h($newUserText); ?>', '<?php echo h($passwordResetText); ?>'];
    setAll();

    // Confirm before submit
    $('#UserAdminEmailForm').submit(function(e) {
        var url = '<?php echo $baseurl; ?>/admin/users/email/true';
        url += '/recipient:' + $('#recipient').val();
        url += '/recipientEmailList:' + $('#UserRecipientEmailList').val();
        url += '/orgNameList:' + $('#UserOrgNameList').val();
        $.get(url, function(data) {
            $("#confirmation_box").html(data);
            openPopup("#confirmation_box");
        });
        return submitAllowed;
    });

});

function submitMailsForm() {
    submitAllowed = true;
    $('#UserAdminEmailForm').submit();
}

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
    if ($("#recipient option:selected").val() == 2) $("#orgNameList").show();
}


</script>
