<?php
$tableData = [
    ['key' => __('UUID'), 'value' => $event['Event']['uuid'], 'class' => 'quickSelect'],
    ['key' => Configure::read('MISP.showorgalternate') ? __('Source Organisation') : __('Org'), 'value' => $event['Orgc']['name']],
];
if (Configure::read('MISP.tagging')) {
    ob_start();
    if (!empty($event['Tag'])): foreach ($event['Tag'] as $tag): ?>
    <span style="padding-right:0;">
        <span class="tagFirstHalf" style="background-color:<?= h($tag['colour']);?>;color:<?= $this->TextColour->getTextColour($tag['colour']);?>"><?= h($tag['name']); ?></span>
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
    'key' => __('Info'),
    'value' => $event['Event']['info']
];
$tableData[] = [
    'key' => __('Published'),
    'class' => $event['Event']['published'] == 0 ? 'background-red bold not-published' : 'published',
    'class_value' => $event['Event']['published'] == 0 ? '' : 'green',
    'html' => $event['Event']['published'] == 0 ? __('No') : sprintf('<span class="green bold">%s</span>', __('Yes')),
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
    ?>
    <h4 class="visibleDL notPublished" ><?= __('You are currently viewing an event from a feed (%s by %s)', h($feed['Feed']['name']), h($feed['Feed']['provider']));?></h4>
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
            <?php foreach ($event['RelatedEvent'] as $i => $relatedEvent): ?>
            <li class="<?php echo $i > $display_threshold ? 'correlation-expanded-area' : ''; ?>" style="<?php echo $i > $display_threshold ? 'display: none;' : ''; ?>">
                <?php echo $this->element('/Events/View/related_event', array('related' => $relatedEvent['Event'])); ?>
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
    <div id="attributes_div">
        <?php echo $this->element('Feeds/eventattribute'); ?>
    </div>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'feeds', 'menuItem' => 'previewEvent', 'id' => $event['Event']['uuid'])); ?>
<script type="text/javascript">
// tooltips
$(function () {
    $("th, td, dt, div, span, li").tooltip({
        'placement': 'top',
        'container' : 'body',
        delay: { show: 500, hide: 100 }
        });
});
</script>
