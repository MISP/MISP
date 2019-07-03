<div class="confirmation">
<?php
    $encryptionMessage = __('WARNING: This user does not have an encryption key set. The security posture of this instance allows for the sending of clear text e-mails, so this is what will happen if you proceed.');
    $encryptionColour = 'white red-background';
    if (!empty($error)) {
        $encryptionMessage = $error;
    }
    $legend = ($firstTime ? __('Send welcome message to user') : __('Initiate password reset for user'));
    $message = ($firstTime ? __('Are you sure you want to reset the password of %s and send him/her a welcome message with the credentials?', $user['User']['email']) : __('Are you sure you want to reset the password of %s and send him/her the temporary credentials? ', $user['User']['email']));
    echo $this->Form->create('User', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend><?php echo $legend; ?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <?php
        if (empty($encryption)):
    ?>
            <div style="width:100%;" class="bold <?php echo $encryptionColour; ?>"><?php echo h($encryptionMessage); ?></div>
    <?php
        endif;
    ?>
    <p><?php echo $message; ?><br />
    <?php echo $this->Form->input('firstTime', array('label' => false, 'type' => 'checkbox', 'div' => false, 'style' => 'border:0px;margin:0px;')); ?><?php echo __('First time registration');?>
    </p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" role="button" tabindex="0" aria-label="<?php echo __('Submit password reset');?>" class="btn btn-primary" onClick="submitPasswordReset('<?php echo $user['User']['id']; ?>');"><?php echo __('Yes');?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
