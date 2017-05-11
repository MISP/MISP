<div class="confirmation">
	<?php
		echo $this->Form->create('Server', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/servers/update'));
	?>
	<legend>Update MISP</legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<p>Do you want to pull the latest commit from the <?php echo h($branch); ?> branch? If you have made local changes to MISP the merge will fail.</p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span role="button" tabindex="0" aria-label="Publish" title="Publish" id="PromptYesButton" class="btn btn-primary" onClick="submitMISPUpdate();">Yes</span>
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
