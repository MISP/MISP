<div class="confirmation">
	<?php
		echo $this->Form->create('Sighting', array('style' => 'margin:0px;', 'id' => 'PromptForm', 'url' => '/sightings/quickDelete/' . $id . '/' . urlencode($rawId) . '/' . $context));
	?>
	<legend>Remove Sighting</legend>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
	<p>Remove sighting (<?php echo h($id); ?>)?</p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<span id="PromptYesButton" role="button" tabindex="0" aria-label="Remove sighting" title="Remove sighting" class="btn btn-primary" data-id="<?php echo h($id); ?>" data-rawid="<?php echo h($rawId); ?>" data-context="<?php echo h($context); ?>" onClick="removeSighting(this);">Yes</span>
				</td>
				<td style="width:540px;">
				</td>
				<td style="vertical-align:top;">
					<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt(1);">No</span>
				</td>
			</tr>
		</table>
	</div>
	<?php
		echo $this->Form->end();
	?>
</div>
