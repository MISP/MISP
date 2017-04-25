<div class="confirmation">
<?php
	echo $this->Form->create('ShadowAttribute', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
?>
<legend>Attribute Deletion</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you want to propose to delete Attribute #<?php echo $id?>?</p>
	<table>
		<tr>
			<td style="vertical-align:top">
				<span role="button" tabindex="0" aria-label="Propose to delete attribute" title="Propose to delete attribute" id="PromptYesButton" class="btn btn-primary" onClick="submitDeletion(<?php echo $event_id; ?>, 'delete', 'shadow_attributes', <?php echo $id;?>)">Yes</span>
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
