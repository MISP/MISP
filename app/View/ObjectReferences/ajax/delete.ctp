<div class="confirmation">
<?php
  $url = '/object_references/delete/' . $id;
  if ($hard) {
    $url .= '/true';
  }
    echo $this->Form->create('ObjectReference', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => $url));
    if ($hard) $hard = '/true';
?>
<legend><?php echo __('Object reference Deletion');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
  $type = 'soft-';
  $typeMessage = __('Are you sure you want to soft delete Object reference #%s?%s');
  if ($hard) {
    $type = 'hard-';
    $typeMessage = __('Are you sure you want to hard delete Object reference #%s?%s');
  }
?>
<p>
  <?php
    echo sprintf(
      $typeMessage,
      $id,
      $hard ? __(' The Attribute will be permanently deleted and unrecoverable. Also, this will prevent the deletion to be propagated to other instances.') : ''
    );
  ?>
</p>
    <table>
        <tr>
            <td style="vertical-align:top">
                <span id="PromptYesButton" title="<?php echo __('Delete');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete');?>" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'delete', 'object_references', '<?php echo $id . $hard;?>')"><?php echo __('Yes');?></span>
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
