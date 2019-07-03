<div class="confirmation">
<?php
    echo $this->Form->create('EventGraph', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend><?php echo __('EventGraph Deletion'); ?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
    $message = __('Are you sure you want to delete eventGraph #%s? The eventGraph will be permanently deleted and unrecoverable.', h($id));
?>
<p><?php echo $message; ?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" title="<?php echo __('Delete'); ?>" role="button" tabindex="0" aria-label="<?php echo __('Delete'); ?>" class="btn btn-primary" onClick="submitDeletion(<?php echo 'scope_id'; ?>, 'delete', 'eventGraph', '<?php echo h($id) ;?>')"><?php echo __('Yes'); ?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span class="btn btn-inverse" title="<?php echo __('No'); ?>" role="button" tabindex="0" aria-label="<?php echo __('No'); ?>" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No'); ?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
