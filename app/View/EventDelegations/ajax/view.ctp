<div class="confirmation">
<legend>Event Delegation</legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
$target = $me['org_id'] == $delegation['Org']['id'] ? 'your organisation' : $delegation['Org']['name'];
$requester = $me['org_id'] == $delegation['RequesterOrg']['id'] ? 'Your organisation' : $delegation['RequesterOrg']['name'];
?>
<p>
<b>Request details</b><br /><span class="red bold"><?php echo h($requester);?></span> is requesting <span class="red bold"><?php echo h($target); ?></span> to take over this event.
<?php if ($delegation['EventDelegation']['distribution'] != -1): ?>
	<?php if ($delegation['EventDelegation']['distribution'] < 4): ?> <br />
	The desired distribution level is <span class="red bold"><?php echo h($delegation['requested_distribution_level']);?></span>
	<?php else: ?>
	The desired sharing group to distribute the event to is: <span class="red bold"><?php echo h($delegation['SharingGroup']['name']);?></span>.
	<?php endif;?>
<?php endif;?>
</p>
<p><b>Message from requester</b><br /><?php echo h($delegation['EventDelegation']['message']); ?></p>
	<div class="row-fluid">
		<?php if ($isSiteAdmin || $me['org_id'] == $delegation['Org']['id']):?>
			<span role="button" tabindex="0" aria-label="Accept delegation request" title="Accept delegation request" class="btn btn-primary" onClick="genericPopup('<?php echo $baseurl?>/event_delegations/acceptDelegation/<?php echo h($delegation['EventDelegation']['id']); ?>', '#confirmation_box');">Accept</span>
		<?php endif;?>
		<span role="button" tabindex="0" aria-label="Decline and remove delegation request" title="Decline and remove delegation request" class="btn btn-inverse" onClick="genericPopup('<?php echo $baseurl?>/event_delegations/deleteDelegation/<?php echo h($delegation['EventDelegation']['id']); ?>', '#confirmation_box');">Discard</span>
		<span role="button" tabindex="0" aria-label="Cancel" title="Cancel" class="btn btn-inverse" style="float:right;" id="PromptNoButton" onClick="cancelPrompt();">Cancel</span>
	</div>
</div>
