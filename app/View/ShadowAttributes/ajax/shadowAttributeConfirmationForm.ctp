<div class="confirmation">
<?php
echo $this->Form->create('ShadowAttribute', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend>Proposal Deletion</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to delete Proposal #<?php echo $id?>?</p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span role="button" tabindex="0" aria-label="Delete proposal" title="Delete proposal" id="PromptYesButton" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'discard', 'shadow_attributes', <?php echo $id;?>)">Yes</span>
			</td>
			<td style="width:540px;">
			</td>
			<td style="vertical-align:top;">
				<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
			</td>
		</tr>
	</table>
</div>
<?php
	echo $this->Form->end();
?>
</div>
