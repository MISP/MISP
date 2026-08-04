<div class="confirmation">
<?php
echo $this->Form->create('ShadowAttribute', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend><?php echo __('Proposal Deletion'); ?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p><?php echo __('Are you sure you want to delete Proposal #%s?', $id);?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span role="button" tabindex="0" aria-label="<?php echo __('Delete proposal');?>" title="<?php echo __('Delete proposal');?>" id="PromptYesButton" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'discard', 'shadow_attributes', <?php echo $id;?>)"><?php echo __('Yes');?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span role="button" tabindex="0" aria-label="<?php echo __('Cancel'); ?>" title="<?php echo __('Cancel'); ?>" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No'); ?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
