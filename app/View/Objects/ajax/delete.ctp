<div class="confirmation">
<?php
    echo $this->Form->create('Object', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
    if ($hard) $hard = '/true';
?>
<legend><?php echo __('Object Deletion');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
    $stringParams = array(
        0 => $hard ? 'hard-' : 'soft-',
        1 => h($id),
        2 => $hard ? ' ' . __('The Object will be permanently deleted and unrecoverable. Also, this will prevent the deletion to be propagated to other instances.') : ''
    );
?>
<p><?php echo __('Are you sure you want to %sdelete Object #%s? %s', $stringParams[0], $stringParams[1], $stringParams[2]);?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" title="<?php echo __('Delete');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete');?>" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'delete', 'objects', '<?php echo $id . $hard;?>')"><?php echo __('Yes');?></span>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span class="btn btn-inverse" title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
            </td>
        </tr>
    </table>
</div>
<?php
    echo $this->Form->end();
?>
</div>
