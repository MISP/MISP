<div class="confirmation">
<?php
    echo $this->Form->create('Attribute', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend><?php echo __('Attribute Restoration'); ?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p><?php echo __('Are you sure you want to undelete Attribute #%s?', h($id)); ?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" class="btn btn-primary" title="<?php echo __('Submit'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Submit'); ?>" onClick="submitDeletion(<?php echo $event_id; ?>, 'restore', 'attributes', <?php echo $id;?>)"><?php echo __('Yes'); ?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span class="btn btn-inverse" id="PromptNoButton" title="<?php echo __('Cancel'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" onClick="cancelPrompt();"><?php echo __('No'); ?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
