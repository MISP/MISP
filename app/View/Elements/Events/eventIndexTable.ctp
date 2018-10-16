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
                    <th class="filter"><?php echo $this->Paginator->sort('Org'); ?></th>
        <?php
                endif;
                if ($isSiteAdmin):
        ?>
            <th class="filter"><?php echo $this->Paginator->sort('owner org');?></th>
        <?php
                endif;
            endif;
            $date = time();
            $day = 86400;
        ?>
        <th><?php echo $this->Paginator->sort('id', null, array('direction' => 'desc'));?></th>
        <th><?php echo __('Clusters');?></th>
        <?php if (Configure::read('MISP.tagging')): ?>
            <th class="filter"><?php echo __('Tags');?></th>
        <?php endif; ?>
        <th title="<?php echo __('Attribute Count');?>"><?php echo $this->Paginator->sort('attribute_count', '#Attr.');?></th>
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
        <th><?php echo $this->Paginator->sort('user_id', 'Email');?></th>
        <?php endif; ?>
        <th class="filter"><?php echo $this->Paginator->sort('date', null, array('direction' => 'desc'));?></th>
        <th class="filter"><?php echo $this->Paginator->sort('info');?></th>
        <th title="<?php echo $eventDescriptions['distribution']['desc'];?>">
            <?php echo $this->Paginator->sort('distribution');?>
        </th>
        <th class="actions">Actions</th>

    </tr>
    <?php foreach ($events as $event): ?>
    <tr <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRed"'?>>
            <?php
                if ($isSiteAdmin || ($event['Event']['orgc_id'] == $me['org_id'])):
            ?>
                    <td style="width:10px;" data-id="<?php echo h($event['Event']['id']); ?>">
                        <input class="select" type="checkbox" data-id="<?php echo $event['Event']['id'];?>" />
                    </td>
            <?php
                else:
            ?>
                    <td style="padding-left:0px;padding-right:0px;"></td>
            <?php
                endif;
            ?>
        <td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
            <?php
            if ($event['Event']['published'] == 1) {
            ?>
                <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>" class = "icon-ok" title = "<?php echo __('View');?>"></a>
            <?php
            } else {
            ?>
                <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>" class = "icon-remove" title = "<?php echo __('View');?>"></a>
            <?php
            }?>&nbsp;
        </td>
        <?php if (Configure::read('MISP.showorg') || $isAdmin): ?>
            <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Orgc']['id'];?>'">
                <?php
                    echo $this->OrgImg->getOrgImg(array('name' => $event['Orgc']['name'], 'id' => $event['Orgc']['id'], 'size' => 24));
                ?>
                &nbsp;
            </td>
        <?php endif;?>
        <?php if ($isSiteAdmin || (Configure::read('MISP.showorgalternate') && Configure::read('MISP.showorg'))): ?>
            <td class="short" ondblclick="document.location.href ='<?php echo $baseurl . "/events/index/searchorg:" . $event['Org']['id'];?>'">
                <?php
                    echo $this->OrgImg->getOrgImg(array('name' => $event['Org']['name'], 'id' => $event['Org']['id'], 'size' => 24));
                ?>
                &nbsp;
            </td>
        <?php endif; ?>
        <td style="width:30px;">
            <a href="<?php echo $baseurl."/events/view/".$event['Event']['id'] ?>"><?php echo $event['Event']['id'];?></a>
        </td>
        <td class="shortish">
            <?php
                $clusterList = array();
                $galaxyList = array();
                $galaxy_id = 0;
                if (isset($event['GalaxyCluster'])):
                    foreach ($event['GalaxyCluster'] as $cluster):
                        $galaxy_id = $cluster['Galaxy']['id'];
                        if (!isset($galaxyList[$cluster['Galaxy']['id']])) {
                            $galaxyList[$cluster['Galaxy']['id']] = $cluster['Galaxy']['name'];
                        }
                        $clusterList[$cluster['Galaxy']['id']][] = array('value' => $cluster['value'], 'id' => $cluster['id'], 'tag_id' => $cluster['tag_id']);
                    endforeach;
                endif;
                $first = true;
                foreach ($clusterList as $galaxy_id => $clusters):
                    if (!$first) {
                        echo '<br />';
                    } else {
                        $first = false;
                    }
                ?>
                    <span class="blue bold"><a href="<?php echo $baseurl; ?>/galaxies/view/<?php echo h($galaxy_id); ?>"><?php echo h($galaxyList[$galaxy_id]); ?></a>:</span>
                <?php
                    foreach ($clusters as $cluster):
                    ?>
                        <br />
                        <span class="blue">
                            &nbsp;
                            <a href="<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($cluster['tag_id']); ?>"><?php echo h($cluster['value']); ?></a>
                            <a href="<?php echo $baseurl; ?>/galaxy_clusters/view/<?php echo h($cluster['id']); ?>" class="icon-search"></a>
                        </span>
                    <?php
                    endforeach;
                endforeach;
            ?>&nbsp;
        </td>
        <?php if (Configure::read('MISP.tagging')): ?>
            <td style = "max-width: 200px;width:10px;">
                <?php foreach ($event['EventTag'] as $tag):
                    $tagText = "&nbsp;";
                    if (Configure::read('MISP.full_tags_on_event_index') == 1) $tagText = h($tag['Tag']['name']);
                    else if (Configure::read('MISP.full_tags_on_event_index') == 2) {
                        if (strpos($tag['Tag']['name'], '=')) {
                            $tagText = explode('=', $tag['Tag']['name']);
                            $tagText = h(trim(end($tagText), "\""));
                        }
                        else $tagText = h($tag['Tag']['name']);
                    }
                ?>
                    <span class="tag useCursorPointer" style="margin-bottom:3px;background-color:<?php echo h($tag['Tag']['colour']);?>;color:<?php echo $this->TextColour->getTextColour($tag['Tag']['colour']);?>;" title="<?php echo h($tag['Tag']['name']); ?>" onClick="document.location.href='<?php echo $baseurl; ?>/events/index/searchtag:<?php echo h($tag['Tag']['id']);?>';"><?php echo $tagText; ?></span>
                <?php endforeach; ?>
            </td>
        <?php endif; ?>
        <td style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'">
            <?php echo $event['Event']['attribute_count']; ?>&nbsp;
        </td>
        <?php if (Configure::read('MISP.showCorrelationsOnIndex')):?>
            <td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['correlation_count']) ? h($event['Event']['correlation_count']) : '0') . __(' correlation(s)');?>">
                <?php echo !empty($event['Event']['correlation_count']) ? h($event['Event']['correlation_count']) : ''; ?>&nbsp;
            </td>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showSightingsCountOnIndex')):?>
            <td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['sightings_count']) ? h($event['Event']['sightings_count']) : '0') . ' sighting(s)';?>">
                <?php echo !empty($event['Event']['sightings_count']) ? h($event['Event']['sightings_count']) : ''; ?>&nbsp;
            </td>
        <?php endif; ?>
        <?php if (Configure::read('MISP.showProposalsOnIndex')): ?>
            <td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : '0') . __(' proposal(s)');?>">
                <?php echo !empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : ''; ?>&nbsp;
            </td>
        <?php endif;?>
        <?php if (Configure::read('MISP.showDiscussionsCountOnIndex')): ?>
            <td class = "bold" style="width:30px;" ondblclick="location.href ='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>'" title="<?php echo (!empty($event['Event']['proposals_count']) ? h($event['Event']['proposals_count']) : '0') . __(' proposal(s)');?>">
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
        <?php if ('true' == $isSiteAdmin): ?>
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
        <td class="short <?php if ($event['Event']['distribution'] == 0) echo 'privateRedText';?>" ondblclick="location.href ='<?php echo $baseurl; ?>/events/view/<?php echo $event['Event']['id'];?>'" title = "<?php echo $event['Event']['distribution'] != 3 ? $distributionLevels[$event['Event']['distribution']] : __('All');?>">
            <?php if ($event['Event']['distribution'] == 4):?>
                <a href="<?php echo $baseurl;?>/sharingGroups/view/<?php echo h($event['SharingGroup']['id']); ?>"><?php echo h($event['SharingGroup']['name']);?></a>
            <?php else:
                echo h($shortDist[$event['Event']['distribution']]);
            endif;
            ?>
        </td>
        <td class="short action-links">
            <?php
                if (0 == $event['Event']['published'] && ($isSiteAdmin || ($isAclPublish && $event['Event']['orgc_id'] == $me['org_id'])))
                    echo $this->Form->postLink('', array('action' => 'alert', $event['Event']['id']), array('class' => 'icon-download-alt', 'title' => __('Publish Event'), __('Are you sure this event is complete and everyone should be informed?')));
                else if (0 == $event['Event']['published']) echo __('Not published');

                if ($isSiteAdmin || ($isAclModify && $event['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $event['Event']['orgc_id'] == $me['org_id'])):
            ?>
                    <a href='<?php echo $baseurl."/events/edit/".$event['Event']['id'];?>' class = "icon-edit" title = "<?php echo __('Edit');?>"></a>
            <?php

                    echo $this->Form->postLink('', array('action' => 'delete', $event['Event']['id']), array('class' => 'icon-trash', 'title' => __('Delete')), __('Are you sure you want to delete # %s?', $event['Event']['id']));
                endif;
            ?>
            <a href='<?php echo $baseurl."/events/view/".$event['Event']['id'];?>' class = "icon-list-alt" title = "<?php echo __('View');?>"></a>
        </td>
    </tr>
    <?php endforeach; ?>
</table>
<script type="text/javascript">
    $(document).ready(function() {
        $('.select').on('change', function() {
            listCheckboxesChecked();
        });
    });
</script>
