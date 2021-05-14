<table class="table table-striped table-hover table-condensed">
    <tr>
        <?php if ($isSiteAdmin): ?>
            <th>
                <input class="select_all select" type="checkbox" title="<?php echo __('Select all');?>" role="button" tabindex="0" aria-label="<?php echo __('Select all events on current page');?>" onClick="toggleAllCheckboxes();" />&nbsp;
            </th>
        <?php else: ?>
            <th style="padding-left:0px;padding-right:0px;">&nbsp;</th>
        <?php endif;?>
        <th class="filter">
            <?php echo $this->Paginator->sort('published');?>
        </th>
        <?php
            if (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg')):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('Org', 'Source org'); ?></th>
            <th class="filter"><?php echo $this->Paginator->sort('Org', 'Member org'); ?></th>
        <?php
            elseif (Configure::read('MISP.showorg') || $isAdmin):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('Org', __('Creator org')); ?></th>
        <?php
                endif;
            $date = time();
            $day = 86400;
        ?>

        <?php if (in_array('owner_org', $columns, true)): ?><th class="filter"><?= $this->Paginator->sort('owner org', __('Owner org')) ?></th><?php endif; ?>
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
        <th class="filter"><?= $this->Paginator->sort('info');?></th>
        <th title="<?= $eventDescriptions['distribution']['desc'];?>">
            <?= $this->Paginator->sort('distribution');?>
        </th>
        <th class="actions"><?php echo __('Actions');?></th>
    </tr>
    <?php foreach ($events as $event): $eventId = (int)$event['Event']['id']; ?>
    <tr id="event_<?= $eventId ?>">
        <?php if ($isSiteAdmin || ($event['Event']['orgc_id'] == $me['org_id'])):?>
        <td style="width:10px;">
            <input class="select" type="checkbox" data-id="<?= $eventId ?>" />
        </td>
        <?php else: ?>
        <td style="padding-left:0;padding-right:0;"></td>
        <?php endif; ?>
        <td class="short dblclickElement">
            <a href="<?= "$baseurl/events/view/$eventId" ?>" title="<?= __('View') ?>" aria-label="<?= __('View') ?>">
                <i class="black fa <?= $event['Event']['published'] == 1 ? 'fa-check' : 'fa-times' ?>"></i>
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
        <td style="width:30px;">
            <a href="<?= $baseurl."/events/view/".$eventId ?>" class="dblclickActionElement threat-level-<?= strtolower(h($event['ThreatLevel']['name'])) ?>" title="<?= __('Threat level: %s', h($event['ThreatLevel']['name'])) ?>"><?= $eventId ?></a>
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
                      'mayModify' => false,
                      'isAclTagger' => false,
                      'data' => $galaxies,
                      'event' => $event,
                      'target_id' => $eventId,
                      'target_type' => 'event',
                      'static_tags_only' => 1
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
                    'tag_display_style' => Configure::check('MISP.full_tags_on_event_index') ? Configure::read('MISP.full_tags_on_event_index') : 1
                ]);
            ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('attribute_count', $columns, true)): ?>
        <td class="dblclickElement" style="width:30px;">
            <?= $event['Event']['attribute_count']; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('correlations', $columns, true)): ?>
        <td class="bold" style="width:30px;">
            <?php if (!empty($event['Event']['correlation_count'])): ?>
                <a href="<?php echo $baseurl."/events/view/" . $eventId . '/correlation:1';?>" title="<?= __n('%s correlation', '%s correlations', $event['Event']['correlation_count'], $event['Event']['correlation_count']), '. ' . __('Show filtered event with correlation only.');?>">
                    <?php echo h($event['Event']['correlation_count']); ?>
                </a>
            <?php endif; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('report_count', $columns, true)): ?>
        <td class="bold" style="width:30px;">
            <?= $event['Event']['report_count']; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('sightings', $columns, true)): ?>
        <td class="bold" style="width:30px;">
            <?php if (!empty($event['Event']['sightings_count'])): ?>
                <a href="<?php echo $baseurl."/events/view/" . $eventId . '/sighting:1';?>" title="<?php echo (!empty($event['Event']['sightings_count']) ? h($event['Event']['sightings_count']) : '0') . ' sighting(s). Show filtered event with sighting(s) only.';?>">
                    <?php echo h($event['Event']['sightings_count']); ?>
                </a>
            <?php endif; ?>
        </td>
        <?php endif; ?>
        <?php if (in_array('proposals', $columns, true)): ?>
        <td class="bold dblclickElement" style="width:30px;" title="<?= __n('%s proposal', '%s proposals', $event['Event']['proposals_count'], $event['Event']['proposals_count']) ?>">
            <?php echo !empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : ''; ?>
        </td>
        <?php endif;?>
        <?php if (in_array('discussion', $columns, true)): ?>
        <td class="bold dblclickElement" style="width:30px;">
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
            <?= $event['Event']['date'] ?>
        </td>
        <td class="dblclickElement">
            <?= nl2br(h($event['Event']['info']), false) ?>
        </td>
        <td class="short dblclickElement <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" title="<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : __('All');?>">
            <?php if ($event['Event']['distribution'] == 4):?>
                <a href="<?php echo $baseurl;?>/sharingGroups/view/<?php echo h($event['SharingGroup']['id']); ?>"><?php echo h($event['SharingGroup']['name']);?></a>
            <?php else:
                echo h($shortDist[$event['Event']['distribution']]);
            endif;
            ?>
            <?php
            echo sprintf(
                '<it type="button" title="%s" class="%s" aria-hidden="true" style="font-size: x-small;" data-event-distribution="%s" data-event-distribution-name="%s" data-scope-id="%s"></it>',
                __('Toggle advanced sharing network viewer'),
                'fa fa-share-alt useCursorPointer distributionNetworkToggle',
                h($event['Event']['distribution']),
                $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($shortDist[$event['Event']['distribution']]),
                $eventId
            )
            ?>
        </td>
        <td class="short action-links">
            <?php
                if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id']))) {
                    echo $this->Form->postLink('', array('action' => 'alert', $eventId), array('class' => 'black fa fa-upload', 'title' => __('Publish Event'), 'aria-label' => __('Publish Event')), __('Are you sure this event is complete and everyone should be informed?'));
                }

                if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id'])):
            ?>
                    <a href="<?php echo $baseurl."/events/edit/".$eventId ?>" title="<?php echo __('Edit');?>" aria-label="<?php echo __('Edit');?>"><i class="black fa fa-edit"></i></a>
            <?php
                    echo sprintf('<a class="useCursorPointer fa fa-trash" title="%s" aria-label="%s" onclick="deleteEvent(%s)"></a>', __('Delete'), __('Delete'), $eventId);
                endif;
            ?>
            <a href="<?php echo $baseurl."/events/view/".$eventId ?>" title="<?php echo __('View');?>" aria-label="<?php echo __('View');?>"><i class="fa black fa-eye"></i></a>
        </td>
    </tr>
    <?php endforeach; ?>
</table>
<script type="text/javascript">
    var lastSelected = false;
    $(function() {
        $('.select').on('change', function() {
            listCheckboxesChecked();
        }).click(function(e) {
            if ($(this).is(':checked')) {
                if (e.shiftKey) {
                    selectAllInbetween(lastSelected, this.id);
                }
                lastSelected = this.id;
            }
            attributeListAnyAttributeCheckBoxesChecked();
        });

        $('.distributionNetworkToggle').each(function() {
            $(this).distributionNetwork({
                distributionData: <?php echo json_encode($distributionData); ?>,
            });
        });
    });

    function deleteEvent(id) {
        var message = "<?= __('Are you sure you want to delete #') ?>" + id + "?"
        var url = '<?= $baseurl ?>/events/delete/' + id
        if (confirm(message)) {
            fetchFormDataAjax(url, function(formData) {
                $('body').append($('<div id="temp" class="hidden"/>').html(formData));
                $('#temp form').submit()
            })
        }
    }
</script>
