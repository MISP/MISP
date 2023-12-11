<table class="table table-striped table-hover table-condensed">
    <tr>
        <th>
            <input class="select_all select" type="checkbox" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all events on current page');?>" onclick="toggleAllCheckboxes();">
        </th>
        <th class="filter" title="<?= __('Published') ?>"><?= $this->Paginator->sort('published', '<i class="fa fa-upload"></i>', ['escape' => false]) ?></th>
        <?php
            if (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg')):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('Orgc.name', __('Source org')); ?></th>
            <th class="filter"><?php echo $this->Paginator->sort('Orgc.name', __('Member org')); ?></th>
        <?php
            elseif (Configure::read('MISP.showorg') || $isAdmin):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('Orgc.name', __('Creator org')); ?></th>
        <?php
                endif;
            $date = time();
            $day = 86400;
        ?>
        <?php if (in_array('owner_org', $columns, true)): ?><th class="filter"><?= $this->Paginator->sort('Org.name', __('Owner org')) ?></th><?php endif; ?>
        <th><?= $this->Paginator->sort('id', __('ID'), ['direction' => 'desc']) ?></th>
        <?php if (in_array('clusters', $columns, true)): ?><th><?= __('Clusters') ?></th><?php endif; ?>
        <?php if (in_array('tags', $columns, true)): ?><th><?= __('Tags') ?></th><?php endif; ?>
        <?php if (in_array('attribute_count', $columns, true)): ?><th title="<?= __('Attribute Count') ?>"><?= $this->Paginator->sort('attribute_count', __('#Attr.')) ?></th><?php endif; ?>
        <?php if (in_array('correlations', $columns, true)): ?><th title="<?= __('Correlation Count')  ?>"><?= __('#Corr.') ?></th><?php endif; ?>
        <?php if (in_array('report_count', $columns, true)): ?><th title="<?= __('Report Count') ?>"><?= $this->Paginator->sort('report_count', __('#Reports')) ?></th><?php endif; ?>
        <?php if (in_array('sightings', $columns, true)): ?><th title="<?= __('Sighting Count')?>"><?= __('#Sightings') ?></th><?php endif; ?>
        <?php if (in_array('proposals', $columns, true)): ?><th title="<?= __('Proposal Count') ?>"><?= __('#Prop') ?></th><?php endif; ?>
        <?php if (in_array('discussion', $columns, true)): ?><th title="<?= __('Post Count') ?>"><?= __('#Posts') ?></th><?php endif; ?>
        <?php if (in_array('creator_user', $columns, true)): ?><th><?= $this->Paginator->sort('user_id', __('Creator user')) ?></th><?php endif; ?>
        <th class="filter"><?= $this->Paginator->sort('date', null, array('direction' => 'desc'));?></th>
        <?php if (in_array('timestamp', $columns, true)): ?><th title="<?= __('Last modified at') ?>"><?= $this->Paginator->sort('timestamp', __('Last modified at')) ?></th><?php endif; ?>
        <?php if (in_array('publish_timestamp', $columns, true)): ?><th title="<?= __('Published at') ?>"><?= $this->Paginator->sort('publish_timestamp', __('Published at')) ?></th><?php endif; ?>
        <th class="filter"><?= $this->Paginator->sort('info');?></th>
        <th title="<?= $eventDescriptions['distribution']['desc'];?>"><?= $this->Paginator->sort('distribution');?></th>
        <th class="actions"><?php echo __('Actions');?></th>
    </tr>
    <?php foreach ($events as $event): $eventId = (int)$event['Event']['id']; ?>
    <tr id="event_<?= $eventId ?>">
        <td style="width:10px">
            <input class="select" type="checkbox" data-id="<?= $eventId ?>" data-can-modify="<?= $this->Acl->canModifyEvent($event) ? 1 : 0 ?>">
        </td>
        <td class="dblclickElement" style="width:30px">
            <a href="<?= "$baseurl/events/view/$eventId" ?>" title="<?= __('View') ?>" aria-label="<?= __('View') ?>">
                <i class="fa <?= $event['Event']['published'] ? 'fa-check green' : 'fa-times grey' ?>"></i>
            </a>
        </td>
        <?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Orgc']['id'];?>'">
            <?= $this->OrgImg->getOrgLogo($event['Orgc'], 24) ?>
        </td>
        <?php endif;?>
        <?php if (in_array('owner_org', $columns, true) || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))): ?>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Org']['id'];?>'">
            <?= $this->OrgImg->getOrgLogo($event['Org'], 24) ?>
        </td>
        <?php endif; ?>
        <td class="short">
            <span><a href="<?= $baseurl."/events/view/".$eventId ?>" class="dblclickActionElement threat-level-<?= strtolower(h($event['ThreatLevel']['name'])) ?>" title="<?= h($event['Event']['info']) ?>"><?= $eventId ?></a> <?= !empty($event['Event']['protected']) ? sprintf('<i class="fas fa-lock" title="%s"></i>', __('Protected event')) : ''?></span>
        </td>
        <?php if (in_array('clusters', $columns, true)): ?>
        <td class="short">
            <?php
                $galaxies = array();
                if (!empty($event['GalaxyCluster'])) {
                    foreach ($event['GalaxyCluster'] as $galaxy_cluster) {
                        $galaxy_id = $galaxy_cluster['Galaxy']['id'];
                        if (!isset($galaxies[$galaxy_id])) {
                            $galaxies[$galaxy_id] = $galaxy_cluster['Galaxy'];
                        }
                        unset($galaxy_cluster['Galaxy']);
                        $galaxies[$galaxy_id]['GalaxyCluster'][] = $galaxy_cluster;
                    }
                    echo $this->element('galaxyQuickViewNew', array(
                      'data' => $galaxies,
                      'event' => $event,
                      'target_id' => $eventId,
                      'target_type' => 'event',
                      'static_tags_only' => true,
                    ));
                }
            ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('tags', $columns, true)): ?>
        <td class="shortish">
            <?= $this->element('ajaxTags', [
                'event' => $event,
                'tags' => $event['EventTag'],
                'tagAccess' => false,
                'localTagAccess' => false,
                'missingTaxonomies' => false,
                'columnised' => true,
                'static_tags_only' => 1,
                'tag_display_style' => Configure::check('MISP.full_tags_on_event_index') ? Configure::read('MISP.full_tags_on_event_index') : 1,
                'highlightedTags' => $event['Event']['highlightedTags'] ?? [],
            ]);
            ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('attribute_count', $columns, true)): ?>
        <td class="dblclickElement" style="width:30px">
            <?= $event['Event']['attribute_count']; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('correlations', $columns, true)): ?>
        <td class="bold" style="width:30px">
            <?php if (!empty($event['Event']['correlation_count'])): ?>
                <a href="<?= "$baseurl/events/view/$eventId/correlation:1" ?>" title="<?= __n('%s correlation', '%s correlations', $event['Event']['correlation_count'], $event['Event']['correlation_count']), '. ' . __('Show filtered event with correlation only.');?>">
                    <?= intval($event['Event']['correlation_count']); ?>
                </a>
            <?php endif; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('report_count', $columns, true)): ?>
        <td class="bold" style="width:30px">
            <?= $event['Event']['report_count']; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('sightings', $columns, true)): ?>
        <td class="bold" style="width:30px">
            <?php if (!empty($event['Event']['sightings_count'])): ?>
                <a href="<?= "$baseurl/events/view/$eventId/sighting:1" ?>" title="<?= __n("1 sighting. Show filtered event with sighting only.", "%s sightings. Show filtered event with sightings only.", $event['Event']['sightings_count'], intval($event['Event']['sightings_count'])) ?>">
                    <?= intval($event['Event']['sightings_count']) ?>
                </a>
            <?php endif; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('proposals', $columns, true)): ?>
        <td class="bold dblclickElement" style="width:30px" title="<?= __n('%s proposal', '%s proposals', $event['Event']['proposals_count'], $event['Event']['proposals_count']) ?>">
            <?= !empty($event['Event']['proposals_count']) ? intval($event['Event']['proposals_count']) : ''; ?>
        </td>
        <?php endif;?>
        <?php if (in_array('discussion', $columns, true)): ?>
        <td class="bold dblclickElement" style="width:30px">
            <?php
                if (!empty($event['Event']['post_count'])) {
                    $post_count = h($event['Event']['post_count']);
                    if (($date - $event['Event']['last_post']) < $day) {
                        $post_count .=  ' (<span class="red bold">' . __('NEW') . '</span>)';
                    }
                } else {
                    $post_count = '';
                }
            ?>
            <span style=" white-space: nowrap;"><?php echo $post_count?></span>
        </td>
        <?php endif;?>
        <?php if (in_array('creator_user', $columns, true)): ?>
        <td class="short dblclickElement">
            <?php echo h($event['User']['email']); ?>
        </td>
        <?php endif; ?>
        <td class="short dblclickElement">
            <time><?= $event['Event']['date'] ?></time>
        </td>
        <?php if (in_array('timestamp', $columns, true)): ?>
        <td class="short dblclickElement">
            <?= $this->Time->time($event['Event']['timestamp']) ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('publish_timestamp', $columns, true)): ?>
        <td class="short dblclickElement">
            <?= $this->Time->time($event['Event']['publish_timestamp']) ?>
        </td>
        <?php endif; ?>
        <td class="dblclickElement">
            <?= nl2br(h($event['Event']['info']), false) ?>
        </td>
        <td class="short dblclickElement<?php if ($event['Event']['distribution'] == 0) echo ' privateRedText';?>" title="<?= $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : __('All');?>">
            <?php if ($event['Event']['distribution'] == 4):?>
                <a href="<?php echo $baseurl;?>/sharingGroups/view/<?= intval($event['SharingGroup']['id']); ?>"><?= h($event['SharingGroup']['name']) ?></a>
            <?php else:
                echo h($shortDist[$event['Event']['distribution']]);
            endif;
            ?>
            <?php
            echo sprintf(
                '<it type="button" title="%s" class="%s" aria-hidden="true" style="font-size: x-small;" data-event-distribution="%s" data-event-distribution-name="%s" data-scope-id="%s"></it>',
                __('Toggle advanced sharing network viewer'),
                'fa fa-share-alt useCursorPointer distributionNetworkToggle',
                intval($event['Event']['distribution']),
                $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($shortDist[$event['Event']['distribution']]),
                $eventId
            )
            ?>
        </td>
        <td class="short action-links">
            <?php
                if (0 == $event['Event']['published'] && $this->Acl->canPublishEvent($event)) {
                    echo sprintf('<a class="useCursorPointer fa fa-upload" title="%s" aria-label="%s" onclick="event.preventDefault();publishPopup(%s)"></a>', __('Publish Event'), __('Publish Event'), $eventId);
                }

                if ($this->Acl->canModifyEvent($event)):
            ?>
                    <a href="<?php echo $baseurl."/events/edit/".$eventId ?>" title="<?php echo __('Edit');?>" aria-label="<?php echo __('Edit');?>"><i class="black fa fa-edit"></i></a>
            <?php
                    echo sprintf('<a class="useCursorPointer fa fa-trash" title="%s" aria-label="%s" onclick="event.preventDefault();deleteEventPopup(%s)"></a>', __('Delete'), __('Delete'), $eventId);
                endif;
            ?>
            <a href="<?php echo $baseurl."/events/view/".$eventId ?>" title="<?php echo __('View');?>" aria-label="<?php echo __('View');?>"><i class="fa black fa-eye"></i></a>
        </td>
    </tr>
    <?php endforeach; ?>
</table>
<script>
    var lastSelected = false;
    $(function() {
        $('.select').on('change', function() {
            listCheckboxesCheckedEventIndex();
        }).click(function(e) {
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this);
                }
                lastSelected = this;
            }
        });

        $('.distributionNetworkToggle').each(function() {
            $(this).distributionNetwork({
                distributionData: <?= json_encode($distributionData, JSON_UNESCAPED_UNICODE); ?>,
            });
        });
    });
</script>
