<div class="eventgraph_header">
    <label id="network-scope" class="btn center-in-network-header network-control-btn">
        <span class="useCursorPointer fa fa-object-group" style="margin-right: 3px;"></span>
        <?php echo __('Scope')?>
        <span id="network-scope-badge" class="badge"></span>
    </label>
    <label id="network-physic" class="btn center-in-network-header network-control-btn"><span class="useCursorPointer fa fa-space-shuttle" style="margin-right: 3px;"></span><?php echo __('Physics')?></label>
    <label id="network-display" class="btn center-in-network-header network-control-btn"><span class="useCursorPointer fa fa-list-alt" style="margin-right: 3px;"></span><?php echo __('Display')?></label>
    <label id="network-filter" class="btn center-in-network-header network-control-btn"><span class="useCursorPointer fa fa-filter" style="margin-right: 3px;"></span><?php echo __('Filters')?></label>
    <label id="network-import" class="btn center-in-network-header network-control-btn"><span class="useCursorPointer fa fa-exchange" style="margin-right: 3px;"></span><?php echo __('Export')?></label>
    <label id="network-history" class="btn center-in-network-header network-control-btn"><span class="useCursorPointer fa fa-history" style="margin-right: 3px;"></span><?php echo __('History')?></label>

    <select id="network-typeahead" class="center-in-network-header network-typeahead flushright position-absolute max-width-400"></select>
</div>

<span class="shortcut-help btn btn-xs btn-info">?</span>
<span id="fullscreen-btn-eventgraph" class="fullscreen-btn btn btn-xs btn-primary" data-toggle="tooltip" data-placement="top" data-title="<?php echo __('Toggle fullscreen');?>"><span class="fa fa-desktop"></span></span>

<div id="eventgraph_shortcuts_background" class="eventgraph_network_background"></div>
<div id="eventgraph_network" class="eventgraph_network" data-event-id="<?php echo h($event['Event']['id']); ?>" data-event-timestamp="<?php echo h($event['Event']['timestamp']); ?>" data-user-manipulation="<?php echo $mayModify || $isSiteAdmin ? 'true' : 'false'; ?>" data-extended="<?php echo $extended; ?>" data-user-email="<?php echo h($me['email']);?>" data-is-site-admin="<?php echo $isSiteAdmin ? 'true' : 'false'; ?>"></div>
<div class="loading-network-div" id="refecences_network_loading_div" style="display: none;">
    <div class="spinner-network" data-original-title="" title=""></div>
    <div class="loadingText-network" data-original-title="" title=""></div>
</div>
<?= $this->element('genericElements/assetLoader', [
     'js' => [
         'vis',
         'bootstrap-typeahead',
         'contextual_menu',
         'action_table',
         'event-graph',
     ],
     'css' => [
         'vis',
         'contextual_menu',
         'action_table',
         'event-graph',
     ],
 ]);
