<div id="eventToggleButtons">
    <button class="btn btn-inverse toggle-left qet" id="pivots_toggle" data-toggle-type="pivots">
        <span class="fas fa-minus" title="<?php echo __('Toggle pivot graph');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle pivot graph');?>"></span><?php echo __('Pivots');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="galaxies_toggle" data-toggle-type="galaxies">
        <span class="fas fa-minus" title="<?php echo __('Toggle galaxies');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle galaxies');?>"></span><?php echo __('Galaxy');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="eventgraph_toggle" data-toggle-type="eventgraph" onclick="enable_interactive_graph();">
        <span class="fas fa-plus" title="<?php echo __('Toggle Event graph');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Event graph');?>"></span><?php echo __('Event graph');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="eventtimeline_toggle" data-toggle-type="eventtimeline" onclick="enable_timeline();">
        <span class="fas fa-plus" title="<?php echo __('Toggle Event timeline');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Event timeline');?>"></span><?php echo __('Event timeline');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="correlationgraph_toggle" data-toggle-type="correlationgraph" data-load-url="<?= $baseurl ?>/events/viewGraph/<?= h($event['Event']['id']) ?>">
        <span class="fas fa-plus" title="<?php echo __('Toggle Correlation graph');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Correlation graph');?>"></span><?php echo __('Correlation graph');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="attackmatrix_toggle" data-toggle-type="attackmatrix" data-load-url="<?= $baseurl; ?>/events/viewGalaxyMatrix/<?= h($event['Event']['id']) ?>/mitre-attack/event/1">
        <span class="fas fa-plus" title="<?php echo __('Toggle ATT&CK matrix');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle ATT&CK matrix');?>"></span><?php echo __('ATT&CK matrix');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="eventreport_toggle" data-toggle-type="eventreport">
        <span class="fas fa-plus" title="<?php echo __('Toggle reports');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle reports');?>"></span><?php echo __('Event reports');?>
    </button>
    <button class="btn btn-inverse toggle qet" id="attributes_toggle" data-toggle-type="attributes">
        <span class="fas fa-minus" title="<?php echo __('Toggle attributes');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle attributes');?>"></span><?php echo __('Attributes');?>
    </button>
    <button class="btn btn-inverse toggle-right qet" id="discussions_toggle" data-toggle-type="discussions">
        <span class="fas fa-minus" title="<?php echo __('Toggle discussions');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle discussions');?>"></span><?php echo __('Discussion');?>
    </button>
</div>
<br />
<br />
<div id="pivots_div">
    <?php if (sizeOf($allPivots) > 1) echo $this->element('pivot'); ?>
</div>
<div id="galaxies_div">
    <span class="title-section"><?= __('Galaxies') ?></span>
    <?= $this->element('galaxyQuickViewNew', [
        'mayModify' => $mayModify,
        'isAclTagger' => $isAclTagger,
        'data' => $event['Galaxy'],
        'event' => $event,
        'target_id' => $event['Event']['id'],
        'target_type' => 'event'
    ]); ?>
</div>
<div id="eventgraph_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false">
    <?php echo $this->element('view_event_graph'); ?>
</div>
<div id="eventtimeline_div" class="info_container_eventtimeline" style="display: none;" data-fullscreen="false">
    <?php echo $this->element('view_timeline'); ?>
</div>
<div id="correlationgraph_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false">
</div>
<div id="attackmatrix_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false">
</div>
<div id="eventreport_div" style="display: none;">
    <span class="report-title-section"><?php echo __('Event Reports');?></span>
    <div id="eventreport_content"></div>
</div>
<div id="clusterrelation_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false">
</div>
<div id="attributes_div">
    <?php echo $this->element('eventattribute'); ?>
</div>
<div id="discussions_div">
</div>
</div>
<script type="text/javascript">
var showContext = false;
$(function () {
<?php
    if (!Configure::check('MISP.disable_event_locks') || !Configure::read('MISP.disable_event_locks')) {
        echo sprintf(
            "queryEventLock('%s', %s);",
            h($event['Event']['id']),
            (int)$event['Event']['timestamp']
        );
    }
?>
popoverStartup();

$(document.body).tooltip({
    selector: 'span[title], td[title], time[title]',
    placement: 'top',
    container: 'body',
    delay: { show: 500, hide: 100 }
}).on('shown', function() {
    $('.tooltip').not(":last").remove();
});

$.get("<?php echo $baseurl; ?>/threads/view/<?php echo h($event['Event']['id']); ?>/true", function(data) {
    $("#discussions_div").html(data);
});

$.get("<?php echo $baseurl; ?>/eventReports/index/event_id:<?= h($event['Event']['id']); ?>/index_for_event:1<?= $extended ? '/extended_event:1' : ''?>", function(data) {
    $("#eventreport_content").html(data);
    if ($('#eventreport_content table tbody > tr').length) { // open if contain a report
        $('#eventreport_toggle').click()
    }
});
});
</script>
