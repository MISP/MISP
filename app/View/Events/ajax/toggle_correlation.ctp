<div class="confirmation">
	<?php
	echo $this->Form->create('Event', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/events/toggleCorrelation/' . $event['Event']['id']));
	$extraTitle = "";
	?>
	<legend>Toggle Correlation <?php echo $event['Event']['disable_correlation'] ? 'on' : 'off'?></legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
		<p>
	<?php
		if ($event['Event']['disable_correlation']) {
			echo 'Re-enable the correlation for this event. This will automatically recorrelate all contained attributes.';
		} else {
			echo 'This will remove all correlations that already exist for the event and prevent any events to be related via correlations as long as this setting is disabled. Make sure you understand the downasides of disabling correlations.';
		}
	?>
	</p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span role="button" tabindex="0" aria-label="Toggle correlation" title="Toggle correlation" id="PromptYesButton" class="btn btn-primary" onClick="submitPublish();">Yes</span>
				</td>
				<td style="width:540px;">
				</td>
				<td style="vertical-align:top;">
					<span class="btn btn-inverse" role="button" tabindex="0" aria-label="Cancel" title="Cancel" id="PromptNoButton" onClick="cancelPrompt();">No</span>
				</td>
			</tr>
		</table>
	</div>
	<?php
		echo $this->Form->end();
	?>
</div>
