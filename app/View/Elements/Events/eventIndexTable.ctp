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
            else:
                if (Configure::read('MISP.showorg') || $isAdmin):
        ?>
                    <th class="filter"><?php echo $this->Paginator->sort('Org', __('Creator org')); ?></th>
        <?php
                endif;
                if ($isSiteAdmin):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('owner org', __('Owner org'));?></th>
        <?php
                endif;
            endif;
            $date = time();
            $day = 86400;
        ?>
        <th><?php echo $this->Paginator->sort('id', __('ID'), array('direction' => 'desc'));?></th>
        <th><?php echo __('Clusters');?></th>
        <?php if (Configure::read('MISP.tagging')): ?>
            <th class="filter"><?php echo __('Tags');?></th>
        <?php endif; ?>
        <th title="<?php echo __('Attribute Count');?>"><?php echo $this->Paginator->sort('attribute_count', __('#Attr.'));?></th>
        <?php if (Configure::read('MISP.showCorrelationsOnIndex')):?>
            <th title="<?php echo __('Correlation Count');?>"><?php echo __('#Corr.');?></th>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showSightingsCountOnIndex')):?>
            <th title="<?php echo __('Sigthing Count');?>"><?php echo __('#Sightings');?></th>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showProposalsOnIndex')):?>
            <th title="<?php echo __('Proposal Count');?>"><?php echo __('#Prop');?></th>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showDiscussionsCountOnIndex')):?>
            <th title="<?php echo __('Post Count');?>"><?php echo __('#Posts');?></th>
        <?php endif; ?>
        <?php if ($isSiteAdmin): ?>
        <th><?php echo $this->Paginator->sort('user_id', __('Creator user'));?></th>
        <?php endif; ?>
        <th class="filter"><?php echo $this->Paginator->sort('date', null, array('direction' => 'desc'));?></th>
        <th class="filter"><?php echo $this->Paginator->sort('info');?></th>
        <th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
            <?php echo $this->Paginator->sort('distribution');?>
        </th>
        <th class="actions"><?php echo __('Actions');?></th>

    </tr>
    <?php foreach ($events as $event): ?>
    <tr <?php if ($event['Event']['distribution'] == 0) echo 'class="privateRed"'?> id="event_<?php echo h($event['Event']['id']);?>">
            <?php
                if ($isSiteAdmin || ($event['Event']['orgc_id'] == $me['org_id'])):
            ?>
                    <td style="width:10px;" data-id="<?php echo h($event['Event']['id']); ?>">
                        <input id="<?php echo h($event['Event']['id']); ?>" class="select" type="checkbox" data-id="<?php echo h($event['Event']['id']);?>" />
                    </td>
            <?php
                else:
            ?>
                    <td style="padding-left:0px;padding-right:0px;"></td>
            <?php
                endif;
            ?>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
            <a href="<?= "$baseurl/events/view/{$event['Event']['id']}" ?>" title="<?= __('View') ?>" aria-label="<?= __('View') ?>">
                <i class="black fa <?= $event['Event']['published'] == 1 ? 'fa-check' : 'fa-times' ?>"></i>
            </a>
        </td>
        <?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
            <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Orgc']['id'];?>'">
                <?= $this->OrgImg->getOrgLogo($event['Orgc'], 24) ?>
            </td>
        <?php endif;?>
        <?php if ($isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))): ?>
            <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Org']['id'];?>'">
                <?= $this->OrgImg->getOrgLogo($event['Org'], 24) ?>
            </td>
        <?php endif; ?>
        <td style="width:30px;">
            <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>"><?php echo $event['Event']['id'];?></a>
        </td>
        <td class="short">
            <?php
                $galaxies = array();
                if (!empty($event['GalaxyCluster'])) {
                    foreach ($event['GalaxyCluster'] as $gk => $galaxy_cluster) {
                        $galaxy_id = $galaxy_cluster['Galaxy']['id'];
                        if (!isset($galaxies[$galaxy_id])) {
                            $galaxies[$galaxy_id] = $galaxy_cluster['Galaxy'];
                        }
                        $galaxy_id = $galaxy_cluster['Galaxy']['id'];
                        unset($galaxy_cluster['Galaxy']);
                        $galaxies[$galaxy_id]['GalaxyCluster'][] = $galaxy_cluster;
                    }
                    echo $this->element('galaxyQuickViewMini', array(
                      'mayModify' => false,
                      'isAclTagger' => false,
                      'data' => $galaxies,
                      'target_id' => $event['Event']['id'],
                      'target_type' => 'event',
                      'static_tags_only' => 1
                    ));
                }
            ?>
        </td>
        <?php
            if (Configure::read('MISP.tagging')) {
                echo sprintf(
                    '<td class="shortish">%s</td>',
                    $this->element(
                        'ajaxTags',
                        array(
                            'event' => $event,
                            'tags' => $event['EventTag'],
                            'tagAccess' => false,
                            'missingTaxonomies' => false,
                            'columnised' => true,
                            'static_tags_only' => 1,
                            'tag_display_style' => Configure::check('MISP.full_tags_on_event_index') ? Configure::read('MISP.full_tags_on_event_index') : 1
                        )
                    )
                );
            }
        ?>
        <td style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
            <?php echo $event['Event']['attribute_count']; ?>&nbsp;
        </td>
        <?php if (Configure::read('MISP.showCorrelationsOnIndex')):?>
            <td class="bold" style="width:30px;">
                <?php if (!empty($event['Event']['correlation_count'])): ?>
                    <a href="<?php echo $baseurl."/events/view/" . h($event['Event']['id']) . '/correlation:1';?>" title="<?php echo h($event['Event']['correlation_count']) . __(' correlation(s). Show filtered event with correlation only.');?>">
                        <?php echo h($event['Event']['correlation_count']); ?>&nbsp;
                    </a>
                <?php endif; ?>
            </td>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showSightingsCountOnIndex')):?>
            <td class="bold" style="width:30px;">
                <?php if (!empty($event['Event']['sightings_count'])): ?>
                    <a href="<?php echo $baseurl."/events/view/" . h($event['Event']['id']) . '/sighting:1';?>" title="<?php echo (!empty($event['Event']['sightings_count']) ? h($event['Event']['sightings_count']) : '0') . ' sighting(s). Show filtered event with sighting(s) only.';?>">
                        <?php echo h($event['Event']['sightings_count']); ?>&nbsp;
                    </a>
                <?php endif; ?>
            </td>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showProposalsOnIndex')): ?>
            <td class="bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : '0') . __(' proposal(s)');?>">
                <?php echo !empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : ''; ?>&nbsp;
            </td>
        <?php endif;?>
        <?php if (Configure::read('MISP.showDiscussionsCountOnIndex')): ?>
            <td class="bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : '0') . __(' proposal(s)');?>">
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
                <span style=" white-space: nowrap;"><?php echo $post_count?></span>&nbsp;
            </td>
        <?php endif;?>
        <?php if ($isSiteAdmin): ?>
            <td class="short" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
                <?php echo h($event['User']['email']); ?>&nbsp;
            </td>
        <?php endif; ?>
        <td class="short" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
            <?php echo $event['Event']['date']; ?>&nbsp;
        </td>
        <td ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
            <?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;
        </td>
        <td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" ondblclick="location.href ='<?php echo $baseurl; ?>/events/view/<?php echo $event['Event']['id'];?>'" title="<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : __('All');?>">
            <?php if ($event['Event']['distribution'] == 4):?>
                <a href="<?php echo $baseurl;?>/sharingGroups/view/<?php echo h($event['SharingGroup']['id']); ?>"><?php echo h($event['SharingGroup']['name']);?></a>
            <?php else:
                echo h($shortDist[$event['Event']['distribution']]);
            endif;
            ?>
            <?php
            echo sprintf(
                '<it type="button" title="%s" class="%s" aria-hidden="true" style="font-size: x-small;" data-event-distribution="%s" data-event-distribution-name="%s" data-scope-id="%s"></it>',
                'Toggle advanced sharing network viewer',
                'fa fa-share-alt useCursorPointer distributionNetworkToggle',
                h($event['Event']['distribution']),
                $event['Event']['distribution'] == 4 ? h($event['SharingGroup']['name']) : h($shortDist[$event['Event']['distribution']]),
                h($event['Event']['id'])
            )
            ?>
        </td>
        <td class="short action-links">
            <?php
                if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id'])))
                    echo $this->Form->postLink('', array('action' => 'alert', $event['Event']['id']), array('class' => 'black fa fa-upload', 'title' => __('Publish Event'), 'aria-label' => __('Publish Event')), __('Are you sure this event is complete and everyone should be informed?'));
                else if (0 == $event['Event']['published']) echo __('Not published');

                if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id'])):
            ?>
                    <a href="<?php echo $baseurl."/events/edit/".$event['Event']['id'];?>" title="<?php echo __('Edit');?>" aria-label="<?php echo __('Edit');?>"><i class="black fa fa-edit"></i></a>
            <?php

                    echo sprintf('<a class="useCursorPointer fa fa-trash" title="%s" aria-label="%s" onclick="deleteEvent(%s)"></a>', __('Delete'), __('Delete'), h($event['Event']['id']));
                endif;
            ?>
            <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'];?>" title="<?php echo __('View');?>" aria-label="<?php echo __('View');?>"><i class="fa black fa-eye"></i></a>
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
