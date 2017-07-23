<div class="confirmation">
<?php
	echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/events/delete'));
  echo $this->Form->hidden('id');
?>
<legend>Event Deletion</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
  $message = 'Are you sure you want to delete ';
  if (count($idArray) > 1) {
    $message .= count($idArray) . ' Events?';
  } else {
    $message .= ' Event #' . $idArray[0] . '?';
  }
?>
<p><?php echo h($message); ?></p>
	<table>
		<tr>
			<td style="vertical-align:top">
        <span class="btn btn-primary" title="Accept" role="button" tabindex="0" aria-label="Accept" id="PromptYesButton" onClick="submitMassEventDelete();">Yes</span>
			</td>
			<td style="width:540px;">
			</td>
			<td style="vertical-align:top;">
				<span class="btn btn-inverse" title="Cancel" role="button" tabindex="0" aria-label="Cancel" id="PromptNoButton" onClick="cancelPrompt();">No</span>
			</td>
		</tr>
	</table>
</div>
<?php
	echo $this->Form->end();
?>
</div>
