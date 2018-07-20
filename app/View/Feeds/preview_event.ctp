<div class="events view">
    <?php
        $title = $event['Event']['info'];
        if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
    ?>
    <h4 class="visibleDL notPublished" ><?php echo __('You are currently viewing an event from a feed (%s by %s)', h($feed['Feed']['name']), h($feed['Feed']['provider']));?></h4>
    <div class="row-fluid">
        <div class="span8">
            <h2><?php echo nl2br(h($title)); ?></h2>
            <dl>
                <dt><?php echo __('Uuid');?></dt>
                <dd><?php echo h($event['Event']['uuid']); ?></dd>
                <dt><?php echo Configure::read('MISP.showorgalternate') ? 'Source Organisation' : 'Org'?></dt>
                <dd><?php echo h($event['Orgc']['name']); ?></dd>
                <?php if (Configure::read('MISP.tagging')): ?>
                    <dt><?php echo __('Tags');?></dt>
                    <dd class="eventTagContainer">
                    <?php if (!empty($event['Tag'])) foreach ($event['Tag'] as $tag): ?>
                        <span style="padding-right:0px;">
                            <span class="tagFirstHalf" style="background-color:<?php echo isset($tag['colour']) ? h($tag['colour']) : 'red';?>;color:<?php echo $this->TextColour->getTextColour(isset($tag['colour']) ? h($tag['colour']) : 'red'); ?>"><?php echo h($tag['name']); ?></span>
                        </span>
                    <?php endforeach; ?>&nbsp;
                    </dd>
                <?php endif; ?>
                <dt>Date</dt>
                <dd>
                    <?php echo h($event['Event']['date']); ?>
                    &nbsp;
                </dd>
                <dt title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>"><?php echo __('Threat Level');?></dt>
                <dd>
                    <?php
                        echo h($threatLevels[$event['Event']['threat_level_id']]);
                    ?>
                    &nbsp;
                </dd>
                <dt title="<?php echo $eventDescriptions['analysis']['desc'];?>"><?php echo __('Analysis');?></dt>
                <dd>
                    <?php echo h($analysisLevels[$event['Event']['analysis']]); ?>
                    &nbsp;
                </dd>
                <dt><?php echo __('Info');?></dt>
                <dd style="word-wrap: break-word;">
                    <?php echo nl2br(h($event['Event']['info'])); ?>
                    &nbsp;
                </dd>
                <?php
                    $published = '';
                    $notPublished = 'style="display:none;"';
                    if ($event['Event']['published'] == 0) {
                        $published = 'style="display:none;"';
                        $notPublished = '';
                    }
                ?>
                        <dt class="published" <?php echo $published;?>><?php echo __('Published');?></dt>
                        <dd class="published green" <?php echo $published;?>><?php echo __('Yes');?></dd>
                <?php
                    if ($isAclPublish) :
                ?>
                        <dt class="visibleDL notPublished" <?php echo $notPublished;?>><?php echo __('Published');?></dt>
                        <dd class="visibleDL notPublished" <?php echo $notPublished;?>><?php echo __('No');?></dd>
                <?php
                    else:
                ?>
                        <dt class="notPublished" <?php echo $notPublished;?>><?php echo __('Published');?></dt>
                        <dd class="notPublished red" <?php echo $notPublished;?>><?php echo __('No');?></dd>
                <?php endif; ?>
            </dl>
        </div>

    <?php if (!empty($event['RelatedEvent'])):?>
    <div class="related span4">
        <h3><?php echo __('Related Events');?></h3>
        <ul class="inline">
            <?php foreach ($event['RelatedEvent'] as $relatedEvent): ?>
            <li>
            <div title="<?php echo h($relatedEvent['Event'][0]['info']); ?>">
            <a href = "<?php echo '/feeds/previewEvent/' . $feed['Feed']['id'] . '/' . $relatedEvent['Event'][0]['uuid']; ?>"><?php echo h($relatedEvent['Event'][0]['date']) . ' (' . h($relatedEvent['Event'][0]['uuid']) . ')'; ?></a>
            </div></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>
    </div>
    <br />
    <div id="attributes_div">
        <?php echo $this->element('Feeds/eventattribute'); ?>
    </div>
</div>
<?php
    echo $this->element('side_menu', array('menuList' => 'feeds', 'menuItem' => 'previewEvent', 'id' => $event['Event']['uuid']));
?>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
    //loadEventTags("<?php echo $event['Event']['id']; ?>");
    $("th, td, dt, div, span, li").tooltip({
        'placement': 'top',
        'container' : 'body',
        delay: { show: 500, hide: 100 }
        });
});
</script>
