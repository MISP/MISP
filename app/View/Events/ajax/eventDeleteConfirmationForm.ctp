<div class="confirmation">
<?php
    echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/events/delete'));
  echo $this->Form->hidden('id');
?>
<legend><?php echo __('Event Deletion');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
  $message = __('Are you sure you want to delete ');
  if (count($idArray) > 1) {
    $message .= count($idArray) . ' Events?';
  } else {
    $message .= __(' Event #') . $idArray[0] . '?';
  }
?>
<p><?php echo h($message); ?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
        <span class="btn btn-primary" title="<?php echo __('Accept');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept');?>" id="PromptYesButton" onClick="submitMassEventDelete();"><?php echo __('Yes');?></span>
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
