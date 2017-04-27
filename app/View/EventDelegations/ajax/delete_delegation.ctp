<div class="confirmation">
	<div class="legend">Delete Delegation Request</div>
	<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
	<p>Are you sure you would like to discard the request by <?php echo h($delegationRequest['RequesterOrg']['name']); ?> to take owenership of Event #<?php echo h($delegationRequest['Event']['id']);?>?</p>
		<table>
			<tr>
				<td style="vertical-align:top">
					<?php
						echo $this->Form->create('EventDelegation', array('style' => 'margin:0px;', 'id' => 'PromptForm'));
						echo $this->Form->submit('Yes', array('div' => false, 'class' => 'btn btn-primary'));
						echo $this->Form->end();
					?>
				</td>
				<td style="width:540px;">
				</td>
				<td style="vertical-align:top;">
					<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
				</td>
			</tr>
		</table>
	</div>
</div>
