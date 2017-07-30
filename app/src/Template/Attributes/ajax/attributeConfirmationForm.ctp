<div class="confirmation">
<?php
	echo $this->Form->create('Attribute', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
	if ($hard) $hard = '/true';
?>
<legend>Attribute Deletion</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to <?php if ($hard) echo 'hard-'; ?>delete Attribute #<?php echo $id?>?<?php if ($hard) echo ' The Attribute will be permanently deleted and unrecoverable. Also, this will prevent the deletion to be propagated to other instances.'; ?></p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span id="PromptYesButton" title="Delete" role="button" tabindex="0" aria-label="Delete" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'delete', 'attributes', '<?php echo $id . $hard;?>')">Yes</span>
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
