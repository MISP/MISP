<div class="confirmation">
<div class="legend">Accept Delegation Request</div>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<p>Are you sure you would like to accept the request by <?php echo h($delegationRequest['RequesterOrg']['name']); ?> to take ownership of Event #<?php echo h($delegationRequest['Event']['id']);?>?</p>
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
					<span title="Cancel" role="button" tabindex="0" aria-label="Cancel" class="btn btn-inverse" id="PromptNoButton" onClick="cancelPrompt();">No</span>
				</td>
			</tr>
		</table>
	</div>
</div>
