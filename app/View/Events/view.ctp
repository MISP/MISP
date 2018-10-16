<?php
    $mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
    $mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
    $csv = array();
    $sightingPopover = '';
    if (isset($event['Sighting']) && !empty($event['Sighting'])) {
        $ownSightings = array();
        $orgSightings = array();
        $sparklineData = array();
        foreach ($event['Sighting'] as $sighting) {
            if (isset($sighting['org_id']) && $sighting['org_id'] == $me['org_id']) $ownSightings[] = $sighting;
            if (isset($sighting['org_id'])) {
                if (isset($orgSightings[$sighting['Organisation']['name']])) {
                    $orgSightings[$sighting['Organisation']['name']]['count']++;
                    if (!isset($orgSightings[$sighting['Organisation']['name']]['date']) || $orgSightings[$sighting['Organisation']['name']]['date'] < $sighting['date_sighting']) {
                        $orgSightings[$sighting['Organisation']['name']]['date'] = $sighting['date_sighting'];
                    }
                } else {
                    $orgSightings[$sighting['Organisation']['name']]['count'] = 1;
                    $orgSightings[$sighting['Organisation']['name']]['date'] = $sighting['date_sighting'];
                }
            } else {
                if (isset($orgSightings['Other organisations']['count'])) {
                    $orgSightings['Other organisations']['count']++;
                    if (!isset($orgSightings['Other organisations']['date']) || $orgSightings['Other organisations']['date'] < $sighting['date_sighting']) {
                        $orgSightings['Other organisations']['date'] = $sighting['date_sighting'];
                    }
                } else {
                    $orgSightings['Other organisations']['count'] = 1;
                    $orgSightings['Other organisations']['date'] = $sighting['date_sighting'];
                }
            }
        }
    }
    echo $this->element('side_menu', array('menuList' => 'event', 'menuItem' => 'viewEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
?>
<div class="events view">
    <?php
        if (Configure::read('MISP.showorg') || $isAdmin):
    ?>
            <div style="float:right;"><?php echo $this->OrgImg->getOrgImg(array('name' => $event['Orgc']['name'], 'id' => $event['Orgc']['id'], 'size' => 48)); ?></div>
    <?php
        endif;
        $title = h($event['Event']['info']);
        if (strlen($title) > 58) $title = substr($title, 0, 55) . '...';
    ?>
    <div class="row-fluid">
        <div class="span8">
            <h2><?php echo ($extended ? '[' . __('Extended view') . '] ' : '') . nl2br($title); ?></h2>
            <dl>
                <dt><?php echo __('Event ID');?></dt>
                <dd>
                    <?php echo h($event['Event']['id']); ?>
                    &nbsp;
                </dd>
                <dt><?php echo __('Uuid');?></dt>
                <dd>
                    <?php echo h($event['Event']['uuid']); ?>
                    &nbsp;
                </dd>
                <?php
                    if (Configure::read('MISP.showorgalternate') && (Configure::read('MISP.showorg') || $isAdmin)): ?>
                        <dt><?php echo __('Source Organisation');?></dt>
                        <dd>
                            <a href="/organisations/view/<?php echo h($event['Orgc']['id']); ?>"><?php echo h($event['Orgc']['name']); ?></a>
                            &nbsp;
                        </dd>
                        <dt><?php echo __('Member Organisation');?></dt>
                        <dd>
                            <a href="/organisations/view/<?php echo h($event['Org']['id']); ?>"><?php echo h($event['Org']['name']); ?></a>
                            &nbsp;
                        </dd>
                <?php
                    else:
                        if (Configure::read('MISP.showorg') || $isAdmin): ?>
                            <dt>Org</dt>
                            <dd>
                                <a href="/organisations/view/<?php echo h($event['Orgc']['id']); ?>"><?php echo h($event['Orgc']['name']); ?></a>
                                &nbsp;
                            </dd>
                            <?php endif; ?>
                            <?php if ($isSiteAdmin): ?>
                            <dt><?php echo __('Owner org');?></dt>
                            <dd>
                                <a href="/organisations/view/<?php echo h($event['Org']['id']); ?>"><?php echo h($event['Org']['name']); ?></a>
                                &nbsp;
                            </dd>
                <?php
                        endif;
                    endif;

                ?>
                <dt><?php echo __('Contributors');?></dt>
                <dd>
                    <?php
                        foreach ($contributors as $k => $entry) {
                            if (Configure::read('MISP.showorg') || $isAdmin) {
                                ?>
                                    <a href="<?php echo $baseurl."/logs/event_index/".$event['Event']['id'].'/'.h($entry);?>" style="margin-right:2px;text-decoration: none;">
                                <?php
                                    echo $this->element('img', array('id' => $entry, 'imgSize' => 24, 'imgStyle' => true));
                                ?>
                                    </a>
                                <?php
                            }
                        }
                    ?>
                    &nbsp;
                </dd>
                <?php
                    if (isset($event['User']['email']) && ($isSiteAdmin || ($isAdmin && $me['org_id'] == $event['Event']['org_id']))):
                ?>
                        <dt><?php echo __('Email');?></dt>
                        <dd>
                            <?php echo h($event['User']['email']); ?>
                            &nbsp;
                        </dd>
                <?php
                    endif;
                    if (Configure::read('MISP.tagging')): ?>
                        <dt><?php echo __('Tags');?></dt>
                        <dd class="eventTagContainer">
                            <?php echo $this->element('ajaxTags', array('event' => $event, 'tags' => $event['EventTag'], 'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['orgc_id']) )); ?>
                        </dd>
                <?php endif; ?>
                <dt><?php echo __('Date');?></dt>
                <dd>
                    <?php echo h($event['Event']['date']); ?>
                    &nbsp;
                </dd>
                <dt title="<?php echo $eventDescriptions['threat_level_id']['desc'];?>"><?php echo __('Threat Level');?></dt>
                <dd>
                    <?php
                        if ($event['ThreatLevel']['name']) echo h($event['ThreatLevel']['name']);
                        else echo h($event['Event']['threat_level_id']);
                    ?>
                    &nbsp;
                </dd>
                <dt title="<?php echo $eventDescriptions['analysis']['desc'];?>"><?php echo __('Analysis');?></dt>
                <dd>
                    <?php echo h($analysisLevels[$event['Event']['analysis']]); ?>
                </dd>
                <dt><?php echo __('Distribution');?></dt>
                <dd <?php if ($event['Event']['distribution'] == 0) echo 'class = "privateRedText"';?> title = "<?php echo h($distributionDescriptions[$event['Event']['distribution']]['formdesc'])?>">
                    <?php
                        if ($event['Event']['distribution'] == 4):
                    ?>
                            <a href="/sharing_groups/view/<?php echo h($event['SharingGroup']['id']); ?>"><?php echo h($event['SharingGroup']['name']); ?></a>
                    <?php
                        else:
                            echo h($distributionLevels[$event['Event']['distribution']]);
                        endif;
                    ?>
                        <span class="useCursorPointer fa fa-info-circle distribution_graph" data-object-id="<?php echo h($event['Event']['id']); ?>" data-object-context="event" data-shown="false"></span>
                        <div style="display: none">
                            <?php echo $this->element('view_event_distribution_graph'); ?>
                        </div>
                </dd>
                <dt><?php echo __('Info');?></dt>
                <dd style="word-wrap: break-word;">
                    <?php echo nl2br(h($event['Event']['info'])); ?>
                    &nbsp;
                </dd>
                <dt class="hidden"></dt><dd class="hidden"></dd>
                <dt class="background-red bold not-published <?php echo ($event['Event']['published'] == 0) ? '' : 'hidden'; ?>"><?php echo __('Published');?></dt>
                <dd class="background-red bold not-published <?php echo ($event['Event']['published'] == 0) ? '' : 'hidden'; ?>"><?php echo __('No');?></dd>
                <dt class="bold published <?php echo ($event['Event']['published'] == 0) ? 'hidden' : ''; ?>"><?php echo __('Published');?></dt>
                <dd class="green bold published <?php echo ($event['Event']['published'] == 0) ? 'hidden' : ''; ?>"><?php echo __('Yes');?></dd>
                <dt><?php echo __('#Attributes');?></dt>
                <dd><?php echo h($attribute_count);?></dd>
                <dt><?php echo __('Last change');?></dt>
                <dd>
                    <?php echo date('Y-m-d H:i:s', $event['Event']['timestamp']);; ?>
                    &nbsp;
                </dd>
                <dt><?php echo __('Extends');?></dt>
                <dd style="word-wrap: break-word;">
                    <?php
                        if (!empty($extendedEvent) && is_array($extendedEvent)) {
                            echo sprintf('<span>%s (<a href="%s">%s</a>): %s</span>', __('Event'), $baseurl . '/events/view/' . h($extendedEvent[0]['Event']['id']), h($extendedEvent[0]['Event']['id']), h($extendedEvent[0]['Event']['info']));
                            echo '&nbsp;<a href="' . $baseurl . '/events/view/' . $extendedEvent[0]['Event']['id'] . '/extended:1"><span class="icon-search"></span></a>';
                        } else {
                            echo h($event['Event']['extends_uuid']);
                        }
                    ?>&nbsp;
                </dd>
                <dt><?php echo __('Extended by');?></dt>
                <dd style="word-wrap: break-word;">
                    <?php
                        foreach ($extensions as $extension) {
                            echo sprintf('<span>%s (<a href="%s">%s</a>): %s</span>', __('Event'), $baseurl . '/events/view/' . h($extension['Event']['id']), h($extension['Event']['id']), h($extension['Event']['info'])) . '<br />';
                        }
                        if (!empty($extensions)) {
                            echo __('Currently in ' . ($extended ? 'extended' : 'atomic') . ' view.') . ' <a href="' . $baseurl . '/events/view/' . $event['Event']['id'] . ($extended ? '' : '/extended:1') . '"><span class="icon-refresh"></span></a>';
                        }
                    ?>&nbsp;
                </dd>
                <dt><?php echo __('Sightings');?></dt>
                <dd style="word-wrap: break-word;">
                        <span id="eventSightingCount" class="bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="<?php echo $sightingPopover; ?>"><?php echo count($event['Sighting']); ?></span>
                        (<span id="eventOwnSightingCount" class="green bold sightingsCounter" data-toggle="popover" data-trigger="hover" data-content="<?php echo $sightingPopover; ?>"><?php echo isset($ownSightings) ? count($ownSightings) : 0; ?></span>)
                        <?php if (!Configure::read('Plugin.Sightings_policy')) echo __('- restricted to own organisation only.'); ?>
                        <span class="icon-wrench useCursorPointer sightings_advanced_add" title="<?php echo __('Advanced Sightings');?>" role="button" tabindex="0" aria-label="<?php echo __('Advanced sightings');?>" data-object-id="<?php echo h($event['Event']['id']); ?>" data-object-context="event">&nbsp;</span>
                </dd>
                <dt><?php echo __('Activity');?></dt>
                <dd>
                    <?php
                        if (!empty($sightingsData['csv']['event'])) {
                            echo $this->element('sparkline', array('id' => $event['Event']['id'], 'csv' => $sightingsData['csv']['event']));
                        } else {
                            echo '&nbsp';
                        }
                    ?>
                </dd>
                <?php
                    if (!empty($delegationRequest)):
                        if ($isSiteAdmin || $me['org_id'] == $delegationRequest['EventDelegation']['org_id']) {
                            // /!\ This is not ideal for i18n not every language has a plural
                            $target = $isSiteAdmin ? $delegationRequest['Org']['name'] : __('you');
                            $subject = $delegationRequest['RequesterOrg']['name'] . __(' has');
                        } else {
                            $target = $delegationRequest['Org']['name'];
                            $subject = __('You have');
                        }
                ?>
                    <dt class="background-red bold"><?php echo __('Delegation request');?></dt>
                    <dd class="background-red bold"><?php echo __('%s requested that %s take over this event.', h($subject), h($target));?> (<a href="#" style="color:white;" onClick="genericPopup('<?php echo $baseurl;?>/eventDelegations/view/<?php echo h($delegationRequest['EventDelegation']['id']);?>', '#confirmation_box');"><?php echo __('View request details');?></a>)</dd>
                <?php endif;?>
                <?php
                    if (!Configure::read('MISP.completely_disable_correlation') && Configure::read('MISP.allow_disabling_correlation')):
                ?>
                        <dt <?php echo $event['Event']['disable_correlation'] ? 'class="background-red bold"' : '';?>><?php echo __('Correlation');?></dt>
                        <dd <?php echo $event['Event']['disable_correlation'] ? 'class="background-red bold"' : '';?>>
                                <?php
                                    if ($mayModify || $isSiteAdmin):
                                        if ($event['Event']['disable_correlation']):
                                ?>
                                            <?php echo __('Disabled');?> (<a onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'events', 'toggleCorrelation', '', '#confirmation_box');" style="color:white;cursor:pointer;font-weight:normal;"><?php echo __('enable');?></a>)
                                <?php
                                        else:
                                ?>
                                            <?php echo __('Enabled');?> (<a onClick="getPopup('<?php echo h($event['Event']['id']); ?>', 'events', 'toggleCorrelation', '', '#confirmation_box');" style="cursor:pointer;font-weight:normal;"><?php echo __('disable');?></a>)
                                <?php
                                        endif;
                                    else:
                                        if ($event['Event']['disable_correlation']):
                                            echo __('Disabled');
                                        else:
                                            echo __('Enabled');
                                        endif;
                                    endif;
                                ?>
                        </dd>
                <?php
                    endif;
                ?>
            </dl>
        </div>
        <div class="related span4">
            <?php
                if (!empty($event['RelatedEvent'])):
            ?>
                    <h3><?php echo __('Related Events');?></h3>
                    <span class="inline">
                        <?php
                            $count = 0;
                            $total = count($event['RelatedEvent']);
                            foreach ($event['RelatedEvent'] as $relatedEvent):
                                $count++;
                                $relatedData = array('Orgc' => $relatedEvent['Event']['Orgc']['name'], 'Date' => $relatedEvent['Event']['date'], 'Info' => $relatedEvent['Event']['info']);
                                $popover = '';
                                foreach ($relatedData as $k => $v) {
                                    $popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
                                }
                                if ($count == 11 && $total > 10):
                                    ?>
                                        <div class="no-side-padding correlation-expand-button useCursorPointer linkButton blue"><?php echo __('Show (%s more)', $total - $count);?></div>
                                    <?php
                                endif;
                        ?>
                                <span data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover" class="<?php if ($count > 11) echo 'correlation-expanded-area'; ?>" style="white-space: nowrap;<?php echo ($count > 10) ? 'display:none;' : ''; ?>">
                        <?php
                                $linkText = $relatedEvent['Event']['date'] . ' (' . $relatedEvent['Event']['id'] . ')';
                                if ($relatedEvent['Event']['orgc_id'] == $me['org_id']) {
                                    echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']), array('style' => 'color:red;'));
                                } else {
                                    echo $this->Html->link($linkText, array('controller' => 'events', 'action' => 'view', $relatedEvent['Event']['id'], true, $event['Event']['id']));
                                }
                        ?>
                                </span>&nbsp;
                        <?php
                            endforeach;
                            if ($total > 10):
                        ?>
                            <div class="no-side-padding correlation-collapse-button useCursorPointer linkButton blue" style="display:none;"><?php echo __('Collapse…');?></div>
                        <?php
                            endif;
                        ?>
                    </span>
            <?php
                endif;
                if (!empty($event['Feed']) || !empty($event['Event']['FeedCount'])):
            ?>
                    <h3>Related Feeds</h3>
            <?php
                    if (!empty($event['Feed'])):
                        foreach ($event['Feed'] as $relatedFeed):
                            $relatedData = array('Name' => $relatedFeed['name'], 'URL' => $relatedFeed['url'], 'Provider' => $relatedFeed['provider'], 'Source Format' => $relatedFeed['source_format'] == 'misp' ? 'MISP' : $relatedFeed['source_format']);
                            $popover = '';
                            foreach ($relatedData as $k => $v) {
                                $popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
                            }
                ?>
                                <span style="white-space: nowrap;">
                                    <?php
                                        if ($relatedFeed ['source_format'] == 'misp'):
                                    ?>
                                            <form action="<?php echo $baseurl; ?>/feeds/previewIndex/<?php echo h($relatedFeed['id']); ?>" method="post" style="margin:0px;">
                                                <input type="hidden" name="data[Feed][eventid]" value="<?php echo h(json_encode($relatedFeed['event_uuids'], true)); ?>">
                                                <input type="submit" class="linkButton useCursorPointer" value="<?php echo h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'; ?>" data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover" />
                                            </form>
                                    <?php
                                        else:
                                    ?>
                                            <a href="<?php echo $baseurl; ?>/feeds/previewIndex/<?php echo h($relatedFeed['id']); ?>" data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover"><?php echo h($relatedFeed['name']) . ' (' . $relatedFeed['id'] . ')'; ?></a><br />
                                    <?php
                                        endif;
                                    ?>
                                </span>
                <?php
                        endforeach;
                    elseif (!empty($event['Event']['FeedCount'])):
                ?>
                        <span>
                            <?php echo __('This event has ');?><span class="bold"><?php echo h($event['Event']['FeedCount']); ?></span>
                            <?php echo __('correlations with data contained within the various feeds, however, due to the large number of attributes the actual feed correlations are not shown. Click (<a href="%s\/overrideLimit:1">here</a> to refresh the page with the feed data loaded.', h($this->here));?>
                     </span>
                <?php
                    endif;
                endif;
            ?>
            <?php if (!empty($event['Event']['warnings'])): ?>
                <div class="warning_container" style="width:80%;">
                    <h4 class="red"><?php echo __('Warning: Potential false positives');?></h4>
                    <?php
                        $total = count($event['Event']['warnings']);
                        $current = 1;
                        foreach ($event['Event']['warnings'] as $id => $name) {
                            echo '<a href="' . $baseurl . '/warninglists/view/' . $id . '">' . h($name) . '</a>' . ($current == $total ? '' : '<br />');
                            $current++;
                        }
                    ?>
                </div>
            <?php endif; ?>
        </div>
    </div>
    <br />
    <div class="toggleButtons">
        <button class="btn btn-inverse toggle-left btn.active qet galaxy-toggle-button" id="pivots_toggle" data-toggle-type="pivots">
            <span class="icon-minus icon-white" title="<?php echo __('Toggle pivot graph');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle pivot graph');?>" style="vertical-align:top;"></span><?php echo __('Pivots');?>
        </button>
        <button class="btn btn-inverse toggle qet galaxy-toggle-button" id="galaxies_toggle" data-toggle-type="galaxies">
            <span class="icon-minus icon-white" title="<?php echo __('Toggle galaxies');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle galaxies');?>" style="vertical-align:top;"></span><?php echo __('Galaxy');?>
        </button>
        <button class="btn btn-inverse toggle qet galaxy-toggle-button" id="eventgraph_toggle" data-toggle-type="eventgraph" onclick="enable_interactive_graph();">
            <span class="icon-plus icon-white" title="<?php echo __('Toggle Event graph');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Event graph');?>" style="vertical-align:top;"></span><?php echo __('Event graph');?>
        </button>
        <button class="btn btn-inverse toggle qet galaxy-toggle-button" id="correlationgraph_toggle" data-toggle-type="correlationgraph" onclick="enable_correlation_graph();">
            <span class="icon-plus icon-white" title="<?php echo __('Toggle Correlation graph');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Correlation graph');?>" style="vertical-align:top;"></span><?php echo __('Correlation graph');?>
        </button>
        <button class="btn btn-inverse toggle qet galaxy-toggle-button" id="attackmatrix_toggle" data-toggle-type="attackmatrix" onclick="enable_attack_matrix();">
            <span class="icon-plus icon-white" title="<?php echo __('Toggle ATT&CK matrix');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle ATT&CK matrix');?>" style="vertical-align:top;"></span><?php echo __('ATT&CK matrix');?>
        </button>
        <button class="btn btn-inverse toggle qet galaxy-toggle-button" id="attributes_toggle" data-toggle-type="attributes">
            <span class="icon-minus icon-white" title="<?php echo __('Toggle attributes');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle attributes');?>" style="vertical-align:top;"></span><?php echo __('Attributes');?>
        </button>
        <button class="btn btn-inverse toggle-right qet galaxy-toggle-button" id="discussions_toggle" data-toggle-type="discussions">
            <span class="icon-minus icon-white" title="<?php echo __('Toggle discussions');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle discussions');?>" style="vertical-align:top;"></span><?php echo __('Discussion');?>
        </button>
    </div>
    <br />
    <br />
    <div id="pivots_div">
        <?php if (sizeOf($allPivots) > 1) echo $this->element('pivot'); ?>
    </div>
    <div id="galaxies_div" class="info_container">
        <h4 class="blue"><?php echo __('Galaxies');?></h4>
        <?php echo $this->element('galaxyQuickView', array('mayModify' => $mayModify, 'isAclTagger' => $isAclTagger, 'data' => $event['Galaxy'], 'target_id' => $event['Event']['id'], 'target_type' => 'event')); ?>
    </div>
    <div id="eventgraph_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false">
        <?php echo $this->element('view_event_graph'); ?>
    </div>
    <div id="correlationgraph_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false">
    </div>
    <div id="attackmatrix_div" class="info_container_eventgraph_network" style="display: none;" data-fullscreen="false" data-mitre-attack-galaxy-id="<?php echo h($mitreAttackGalaxyId)?>">
    </div>
    <div id="attributes_div">
        <?php echo $this->element('eventattribute'); ?>
    </div>
    <div id="discussions_div">
    </div>
    <div id="attribute_creation_div" style="display:none;">
    </div>
</div>
<script type="text/javascript">
var showContext = false;
$(document).ready(function () {
    queryEventLock('<?php echo h($event['Event']['id']); ?>', '<?php echo h($me['org_id']); ?>');
    popoverStartup();

    $("th, td, dt, div, span, li").tooltip({
        'placement': 'top',
        'container' : 'body',
        delay: { show: 500, hide: 100 }
    });

    $.get("/threads/view/<?php echo h($event['Event']['id']); ?>/true", function(data) {
        $("#discussions_div").html(data);
    });
});

function enable_correlation_graph() {
    $.get("/events/viewGraph/<?php echo h($event['Event']['id']); ?>", function(data) {
        $("#correlationgraph_div").html(data);
    });
}

function enable_attack_matrix() {
    $.get("/events/viewMitreAttackMatrix/<?php echo h($event['Event']['id']); ?>", function(data) {
        $("#attackmatrix_div").html(data);
    });
}
</script>
<input type="hidden" value="/shortcuts/event_view.json" class="keyboardShortcutsConfig" />
