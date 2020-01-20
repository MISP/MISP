<?php
    $mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
    $mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
?>

<div>
    <div id="timeline-header" class="eventgraph_header">
        <label id="timeline-scope" class="btn center-in-network-header network-control-btn">
            <span class="useCursorPointer fa fa-object-group" style="margin-right: 3px;"></span><?php echo __('Time scope')?>
        </label>
        <label id="timeline-display" class="btn center-in-network-header network-control-btn">
            <span class="useCursorPointer fa fa-list-alt" style="margin-right: 3px;"></span><?php echo __('Display')?>
            <span id="timeline-display-badge" class="badge"></span>
        </label>
        <select id="timeline-typeahead" class="center-in-network-header network-typeahead flushright position-absolute max-width-400" style="display:none" data-provide="typeahead" size="20" placeholder="Search for an item">
        </select>
    </div>


    <div id="event_timeline" style="min-height: 100px;" data-user-manipulation="<?php echo $mayModify || $isSiteAdmin ? 'true' : 'false'; ?>" data-extended="<?php echo $extended; ?>">
        <div class="loadingTimeline">
            <div class="spinner"></div>
            <div class="loadingText"><?php echo __('Loading');?></div>
        </div>
    </div>
    <span id="fullscreen-btn-timeline" class="fullscreen-btn-timeline btn btn-xs btn-primary" data-toggle="tooltip" data-placement="top" data-title="<?php echo __('Toggle fullscreen');?>"><span class="fa fa-desktop"></span></span>
</div>

<?php
    echo $this->Html->script('moment-with-locales');
    echo $this->Html->script('event-timeline');
    echo $this->Html->css('event-timeline');
?>
