<div class="confirmation">
<?php
    echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $baseurl . '/events/delete'));
    echo $this->Form->hidden('id');
?>
<legend><?php echo __('Event Deletion');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
  if (count($idArray) > 1) {
      $message = __('Are you sure you want to delete %s events?', count($idArray));
  } else {
      $message = __('Are you sure you want to delete event #%s?', $idArray[0]);
  }
?>
<p><?= h($message); ?></p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <button class="btn btn-primary" title="<?php echo __('Accept');?>" role="button" tabindex="0" aria-label="<?php echo __('Accept');?>" id="PromptYesButton"><?php echo __('Yes');?></button>
            </td>
            <td style="width:540px;">
            </td>
            <td style="vertical-align:top;">
                <span class="btn btn-inverse" title="<?php echo __('Cancel');?>" role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('No');?></span>
            </td>
        </tr>
    </table>
</div>
<?= $this->Form->end(); ?>
</div>
