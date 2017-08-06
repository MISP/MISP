<div class="confirmation">
<?php
	echo $this->Form->create('Object', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
	if ($hard) $hard = '/true';
?>
<legend>Object Deletion</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to <?php if ($hard) echo 'hard-'; ?>delete Object #<?php echo $id?>?<?php if ($hard) echo ' The Object will be permanently deleted and unrecoverable. Also, this will prevent the deletion to be propagated to other instances.'; ?></p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span id="PromptYesButton" title="Delete" role="button" tabindex="0" aria-label="Delete" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'delete', 'objects', '<?php echo $id . $hard;?>')">Yes</span>
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
