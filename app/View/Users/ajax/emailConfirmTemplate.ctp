<div class="confirmation">
    <legend><?php echo __('Confirm sending'); ?> </legend>
    <div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
    <p><?php echo __('You are about to send a mail to %s recipient(s)?', '<strong>' . h($emailsCount) . '</strong>'); ?></p>
        <div>
            <select multiple=1 size=15 style="width: 100%">
            <?php foreach($emails as $email): ?>
                    <option><?php echo h($email); ?></option>
            <?php endforeach; ?>
            </select>
        </div>
        <div>
            <span role="button" tabindex="0" aria-label="<?php echo __('Send');?>" title="<?php echo __('Send');?>" class="btn btn-primary" id="PromptYesButton" onClick="submitMailsForm();"><?php echo __('Send');?></span>
            <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" id="PromptNoButton" style="float:right;" onClick="cancelPrompt();"><?php echo __('Cancel');?></span>
        </div>
    </div>
</div>
