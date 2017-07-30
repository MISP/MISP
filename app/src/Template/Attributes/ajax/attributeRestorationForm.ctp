<div class="confirmation">
<?php
	echo $this->Form->create('Attribute', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend>Attribute Restoration</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to undelete Attribute #<?php echo $id?>?</p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span id="PromptYesButton" class="btn btn-primary" title="Submit" role="button" tabindex="0" aria-label="Submit" onClick="submitDeletion(<?php echo $event_id; ?>, 'restore', 'attributes', <?php echo $id;?>)">Yes</span>
			</td>
			<td style="width:540px;">
			</td>
			<td style="vertical-align:top;">
				<span class="btn btn-inverse" id="PromptNoButton" title="Cancel" role="button" tabindex="0" aria-label="Cancel" onClick="cancelPrompt();">No</span>
			</td>
		</tr>
	</table>
</div>
<?php
	echo $this->Form->end();
?>
</div>
