<div class="confirmation">
<legend><?php echo __('Event Delegation');?></legend>
<div style="padding-left:5px;padding-right:5px;padding-bottom:5px;">
<?php
$target = $me['org_id'] == $delegation['Org']['id'] ? __('your organisation') : $delegation['Org']['name'];
$requester = $me['org_id'] == $delegation['RequesterOrg']['id'] ? __('Your organisation') : $delegation['RequesterOrg']['name'];
?>
<p>
<b><?php echo __('Request details</b><br /><span class="red bold">%s</span> is requesting <span class="red bold">%s</span> to take over this event.', h($requester), h($target));?>
<?php if ($delegation['EventDelegation']['distribution'] != -1): ?>
    <?php if ($delegation['EventDelegation']['distribution'] < 4): ?> <br />
    <?php echo __('The desired distribution level is');?> <span class="red bold"><?php echo h($delegation['requested_distribution_level']);?></span>
    <?php else: ?>
    <?php echo __('The desired sharing group to distribute the event to is');?>: <span class="red bold"><?php echo h($delegation['SharingGroup']['name']);?></span>.
    <?php endif;?>
<?php endif;?>
</p>
<p><b><?php echo __('Message from requester');?></b><br /><?php echo h($delegation['EventDelegation']['message']); ?></p>
    <div class="row-fluid">
        <?php if ($isSiteAdmin || $me['org_id'] == $delegation['Org']['id']):?>
            <span role="button" tabindex="0" aria-label="<?php echo __('Accept delegation request');?>" title="<?php echo __('Accept delegation request');?>" class="btn btn-primary" onClick="genericPopup('<?php echo $baseurl?>/event_delegations/acceptDelegation/<?php echo h($delegation['EventDelegation']['id']); ?>', '#confirmation_box');"><?php echo __('Accept');?></span>
        <?php endif;?>
        <span role="button" tabindex="0" aria-label="<?php echo __('Decline and remove delegation request');?>" title="<?php echo __('Decline and remove delegation request');?>" class="btn btn-inverse" onClick="genericPopup('<?php echo $baseurl?>/event_delegations/deleteDelegation/<?php echo h($delegation['EventDelegation']['id']); ?>', '#confirmation_box');"><?php echo __('Discard');?></span>
        <span role="button" tabindex="0" aria-label="<?php echo __('Cancel');?>" title="<?php echo __('Cancel');?>" class="btn btn-inverse" style="float:right;" id="PromptNoButton" onClick="cancelPrompt();"><?php echo __('Cancel');?></span>
    </div>
</div>
