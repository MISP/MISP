<div class="confirmation">
	<?php
	echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/events/' . $type . '/' . $id));
	$extraTitle = "";
	if ($type == 'publish') $extraTitle = ' (no email)';
	?>
	<legend>Publish Event<?php echo $extraTitle; ?></legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<?php
			if ($type == 'alert'):
		?>
				<p>Are you sure this event is complete and everyone should be informed?</p>
		<?php
			else:
		?>
				<p>Publish but do NOT send alert email? Only for minor changes!</p>
		<?php
			endif;
		?>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span role="button" tabindex="0" aria-label="Publish" title="Publish" id="PromptYesButton" class="btn btn-primary" onClick="submitPublish()">Yes</span>
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
