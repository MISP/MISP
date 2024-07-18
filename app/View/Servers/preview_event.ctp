<?php
$tableData = [
    ['key' => __('Event ID'), 'value' => $event['Event']['id']],
    ['key' => __('UUID'), 'value' => $event['Event']['uuid'], 'class' => 'quickSelect'],
    ['key' => Configure::read('MISP.showorgalternate') ? __('Source Organisation') : __('Org'), 'value' => $event['Orgc']['name']],
    ['key' => Configure::read('MISP.showorgalternate') ? __('Member Organisation') : __('Owner Org'), 'value' => $event['Org']['name']],
];

if (Configure::read('MISP.tagging')) {
    ob_start();
    if (!empty($event['Tag'])): foreach ($event['Tag'] as $tag): ?>
    <span style="padding-right:0;">
        <span role="button" tabindex="0" aria-label="<?= __('Filter the remote instance by tag: %s', h($tag['name']));?>" title="<?= __('Filter the remote instance on the tag: %s', h($tag['name'])); ?>" onclick="document.location.href='<?= $baseurl . "/servers/previewIndex/" . h($server['Server']['id']); ?>/searchtag:<?= h($tag['id']); ?>';" class="tagFirstHalf" style="background-color:<?= h($tag['colour']);?>;color:<?= $this->TextColour->getTextColour($tag['colour']);?>"><?= h($tag['name']); ?></span>
    </span>
    <?php endforeach; endif;
    $tags = ob_get_clean();

    $tableData[] = ['key' => __('Tags'), 'html' => $tags];
}
$tableData[] = ['key' => __('Date'), 'html' => $this->Time->time($event['Event']['date'])];
$tableData[] = [
    'key' => __('Threat Level'),
    'key_title' => $eventDescriptions['threat_level_id']['desc'],
    'value' => $threatLevels[$event['Event']['threat_level_id']],
    'value_class' => 'threat-level-' . strtolower($threatLevels[$event['Event']['threat_level_id']]),
];
$tableData[] = [
    'key' => __('Analysis'),
    'key_title' => $eventDescriptions['analysis']['desc'],
    'value' => $analysisLevels[$event['Event']['analysis']],
];
$tableData[] = [
    'key' => __('Distribution'),
    'value_class' => $event['Event']['distribution'] == 0 ? 'privateRedText' : '',
    'html' => $event['Event']['distribution'] == 4 ?
            h($event['SharingGroup']['name']) :
            h($distributionLevels[$event['Event']['distribution']]),
];
$tableData[] = [
    'key' => __('Info'),
    'value' => $event['Event']['info']
];
$tableData[] = [
    'key' => __('Published'),
    'class' => $event['Event']['published'] == 0 ? 'background-red bold not-published' : 'published',
    'class_value' => $event['Event']['published'] == 0 ? '' : 'green',
    'html' => $event['Event']['published'] == 0 ? __('No') : sprintf('<span class="green bold">%s</span>', __('Yes')) . ((empty($event['Event']['publish_timestamp'])) ? __('N/A') :  ' (' . $this->Time->time($event['Event']['publish_timestamp'])) . ')',
];
$tableData[] = [
    'key' => __('Last change'),
    'html' => $this->Time->time($event['Event']['timestamp']),
];
?>
<div class="events view">
    <?php
        $title = $event['Event']['info'];
        if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
        $serverName = $server['Server']['name'] ? '"' . $server['Server']['name'] . '" (' . $server['Server']['url'] . ')' : '"' . $server['Server']['url'] . '"';
    ?>
    <h4 class="visibleDL notPublished"><?php echo __('You are currently viewing an event on the remote instance %s ', h($serverName));?></h4>
    <div class="row-fluid">
        <div class="span8">
            <h2><?php echo nl2br(h($title)); ?></h2>
            <?= $this->element('genericElements/viewMetaTable', array('table_data' => $tableData)); ?>
        </div>
    <?php if (!empty($event['RelatedEvent'])):?>
    <div class="related span4">
        <h3><?php echo __('Related Events');?></h3>
        <ul class="inline">
            <?php
                $total = count($event['RelatedEvent']);
                $display_threshold = 10;
            ?>
            <?php foreach ($event['RelatedEvent'] as $i => $relatedEvent):
                if (isset($relatedEvent['Event'][0])) $relatedEvent['Event'] = $relatedEvent['Event'][0];
            ?>
            <li class="<?php echo $i > $display_threshold ? 'correlation-expanded-area' : ''; ?>" style="<?php echo $i > $display_threshold ? 'display: none;' : ''; ?>">
                <?php echo $this->element('/Events/View/related_event', array(
                    'ownOrg' => $relatedEvent['Event']['orgc_id'] == $me['org_id'],
                    'related' => $relatedEvent['Event'],
                    'relatedEventCorrelationCount' => array(),
                    'href_url' => $baseurl . '/servers/previewEvent/' . $server['Server']['id']
                )); ?>
            </li>
            <?php if ($i == $display_threshold+1 && $total > $display_threshold): ?>
                <div class="no-side-padding correlation-expand-button useCursorPointer linkButton blue"><?php echo __('Show (%s more)', $total - $i);?></div>
            <?php endif; ?>
            <?php endforeach; ?>
            <?php if ($total > $display_threshold): ?>
                <div class="no-side-padding correlation-collapse-button useCursorPointer linkButton blue" style="display:none;"><?php echo __('Collapse…');?></div>
            <?php endif; ?>
        </ul>
    </div>
    <?php endif; ?>
    </div>
    <br />
    <?php if (!empty($event['Galaxy'])): ?>
    <div id="galaxies_div">
        <span class="title-section"><?= __('Galaxies') ?></span>
        <?= $this->element('galaxyQuickViewNew', [
            'data' => $event['Galaxy'],
            'event' => $event,
            'preview' => true,
        ]); ?>
    </div>
    <?php endif; ?>
    <div id="attributes_div">
        <?php echo $this->element('Servers/eventattribute'); ?>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'sync', 'menuItem' => 'previewEvent', 'id' => $event['Event']['id'])); ?>
<script type="text/javascript">
// tooltips
$(function () {
    popoverStartup();
    $("th, td, dt, div, span, li").tooltip({
        'placement': 'top',
        'container' : 'body',
        delay: { show: 500, hide: 100 }
    });
});
</script>
