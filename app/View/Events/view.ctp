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
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event', 'menuItem' => 'viewEvent', 'mayModify' => $mayModify, 'mayPublish' => $mayPublish));
    echo $this->Html->script('doT');
    echo $this->Html->script('extendext');
    echo $this->Html->script('moment-with-locales');
    echo $this->Html->css('query-builder.default');
    echo $this->Html->script('query-builder');
    echo $this->Html->css('attack_matrix');
    echo $this->Html->script('network-distribution-graph');
?>
<div class="events view">
    <?php
        if (Configure::read('MISP.showorg') || $isAdmin):
    ?>
            <div style="float:right;"><?php echo $this->OrgImg->getOrgImg(array('name' => $event['Orgc']['name'], 'id' => $event['Orgc']['id'], 'size' => 48)); ?></div>
    <?php
        endif;
        $title = h($event['Event']['info']);
        $table_data = array();
        $table_data[] = array('key' => __('Event ID'), 'value' => $event['Event']['id']);
        $table_data[] = array(
            'key' => 'UUID',
            'html' => sprintf('%s %s',
                $event['Event']['uuid'],
                sprintf('<a href="%s/events/add/extends:%s" class="btn btn-inverse noPrint" style="line-height: 10px; padding: 4px 4px;" title="%s">+</a>',
                    $baseurl,
                    $event['Event']['id'],
                    __('Extend this event')
                )
            )
        );
        if (Configure::read('MISP.showorgalternate')) {
            $table_data[] = array(
                'key' => __('Source Organisation'),
                'html' => sprintf(
                    '<a href="%s/organisations/view/%s">%s</a>',
                    $baseurl,
                    h($event['Orgc']['id']),
                    h($event['Orgc']['name'])
                )
            );
            $table_data[] = array(
                'key' => __('Member Organisation'),
                'html' => sprintf(
                    '<a href="%s/organisations/view/%s">%s</a>',
                    $baseurl,
                    h($event['Org']['id']),
                    h($event['Org']['name'])
                )
            );
        } else {
            $table_data[] = array(
                'key' => __('Creator org'),
                'html' => sprintf(
                    '<a href="%s/organisations/view/%s">%s</a>',
                    $baseurl,
                    h($event['Orgc']['id']),
                    h($event['Orgc']['name'])
                )
            );
            if ($isSiteAdmin) {
                $table_data[] = array(
                    'key' => __('Owner org'),
                    'html' => sprintf(
                        '<a href="%s/organisations/view/%s">%s</a>',
                        $baseurl,
                        h($event['Org']['id']),
                        h($event['Org']['name'])
                    )
                );
            }
        }
        if (!empty($contributors)) {
            $contributorsContent = '';
            foreach ($contributors as $k => $entry) {
                $contributorsContent .= sprintf(
                    '<a href="%s" style="margin-right:2px;text-decoration: none;">%s</a>',
                    $baseurl . "/logs/event_index/" . $event['Event']['id'] . '/' . h($entry['Organisation']['name']),
                    $this->OrgImg->getOrgImg(array('name' => $entry['Organisation']['name'], 'id' => $entry['Organisation']['id'], 'size' => 24), true, true)
                );
            }
            $table_data[] = array(
                'key' => __('Contributors'),
                'html' => $contributorsContent
            );
        }
        if (isset($event['User']['email']) && ($isSiteAdmin || ($isAdmin && $me['org_id'] == $event['Event']['org_id']))) {
            $table_data[] = array(
                'key' => __('Email'),
                'value' => h($event['User']['email'])
            );
        }
        $table_data[] = array(
            'key' => __('Tags'),
            'html' => sprintf(
                '<span class="eventTagContainer">%s</span>',
                $this->element(
                    'ajaxTags',
                    array(
                        'event' => $event,
                        'tags' => $event['EventTag'],
                        'tagAccess' => ($isSiteAdmin || $mayModify || $me['org_id'] == $event['Event']['orgc_id']),
                        'required_taxonomies' => $required_taxonomies,
                        'tagConflicts' => $tagConflicts
                    )
                )
            )
        );
        $table_data[] = array(
            'key' => __('Date'),
            'value' => $event['Event']['date']
        );
        if (empty(Configure::read('MISP.disable_threat_level'))) {
            $table_data[] = array(
                'key' => __('Threat Level'),
                'key_title' => $eventDescriptions['threat_level_id']['desc'],
                'value' => $event['ThreatLevel']['name']
            );
        }
        $table_data[] = array(
            'key' => __('Analysis'),
            'key_title' => $eventDescriptions['analysis']['desc'],
            'value' => $analysisLevels[$event['Event']['analysis']]
        );
        $table_data[] = array(
            'key' => __('Distribution'),
            'value_class' => ($event['Event']['distribution'] == 0) ? 'privateRedText' : '',
            'html' => sprintf(
                '%s %s %s %s',
                ($event['Event']['distribution'] == 4) ?
                    sprintf('<a href="%s%s">%s</a>', $baseurl . '/sharing_groups/view/', h($event['SharingGroup']['id']), h($event['SharingGroup']['name'])) :
                    h($distributionLevels[$event['Event']['distribution']]),
                sprintf(
                    '<span id="distribution_graph_bar" style="margin-left: 5px;" data-object-id="%s" data-object-context="event"></span>',
                    h($event['Event']['id'])
                ),
                sprintf(
                    '<it class="%s" data-object-id="%s" data-object-context="event" data-shown="false"></it><div style="display: none">%s</div>',
                    'useCursorPointer fa fa-info-circle distribution_graph',
                    h($event['Event']['id']),
                    $this->element('view_event_distribution_graph')
                ),
                sprintf(
                    '<it type="button" id="showAdvancedSharingButton" title="%s" class="%s" aria-hidden="true" style="margin-left: 5px;"></it>',
                    __('Toggle advanced sharing network viewer'),
                    'fa fa-share-alt useCursorPointer'
                )
            )
        );
        $table_data[] = array(
            'key' => __('Info'),
            'value' => $event['Event']['info']
        );
        $table_data[] = array(
            'key' => __('Published'),
            'class' => ($event['Event']['published'] == 0) ? 'background-red bold not-published' : 'published',
            'class_value' => ($event['Event']['published'] == 0) ? '' : 'green',
            'html' => ($event['Event']['published'] == 0) ? __('No') : sprintf('<span class="green bold">%s</span>', __('Yes')) . ((empty($event['Event']['publish_timestamp'])) ? __('N/A') :  ' (' . date('Y-m-d H:i:s', ($event['Event']['publish_timestamp'])) . ')')
        );
        $attribute_text = $attribute_count;
        $attribute_text .= $object_count > 1 ? sprintf(__(' (%s Objects)'), h($object_count)) : sprintf(__(' (%s Object)'), h($object_count));
        $table_data[] = array(
            'key' => __('#Attributes'),
            'value' => $attribute_text
        );
        $table_data[] = array(
            'key' => __('First recorded change'),
            'value' => (!$oldest_timestamp) ? '' : date('Y-m-d H:i:s', $oldest_timestamp)
        );
        $table_data[] = array(
            'key' => __('Last change'),
            'value' => date('Y-m-d H:i:s', $event['Event']['timestamp'])
        );
        $table_data[] = array(
            'key' => __('Modification map'),
            'element' => 'sparkline',
            'element_params' => array('scope' => 'modification', 'id' => $event['Event']['id'], 'csv' => $modificationMapCSV)
        );
        if (!empty($extendedEvent) || !empty($event['Event']['extends_uuid'])) {
            $table_data[] = array(
                'key' => __('Extends'),
                'value_class' => 'break-word',
                'html' => (!empty($extendedEvent) && is_array($extendedEvent)) ?
                    sprintf(
                        '<span>%s (<a href="%s">%s</a>): %s</span>',
                        __('Event'),
                        $baseurl . '/events/view/' . h($extendedEvent[0]['Event']['id']),
                        h($extendedEvent[0]['Event']['id']),
                        h($extendedEvent[0]['Event']['info'])
                    ) :
                    h($event['Event']['extends_uuid'])
            );
        }
        $extended_by = '';
        if (!empty($extensions)) {
            foreach ($extensions as $extension) {
                $extended_by .= sprintf('<span>%s (<a href="%s">%s</a>): %s</span>', __('Event'), $baseurl . '/events/view/' . h($extension['Event']['id']), h($extension['Event']['id']), h($extension['Event']['info'])) . '<br />';
            }
            $table_data[] = array(
                'key' => __('Extended by'),
                'value_class' => 'break-word',
                'html' => sprintf(
                    '%s %s %s',
                    $extended_by,
                    sprintf(
                        'Currently in %s view.',
                        $extended ? __('extended') : __('atomic')
                    ),
                    sprintf(
                        '<a href="%s/events/view/%s%s"><span class="fa fa-sync"></span></a>',
                        $baseurl,
                        $event['Event']['id'],
                        ($extended ? '' : '/extended:1')
                    )
                )
            );
        }
        $table_data[] = array(
            'key' => __('Sightings'),
            'element' => '/Events/View/eventSightingValue',
            'element_params' => array(
                'sightingPopover' => $sightingPopover,
                'event' => $event,
                'ownSightings' => empty($ownSightings) ? array() : $ownSightings
            )
        );
        if (!empty($sightingsData['csv']['event'])) {
            $table_data[] = array(
                'key' => __('Activity'),
                'element' => 'sparkline',
                'element_params' => array('scope' => 'event', 'id' => $event['Event']['id'], 'csv' => $sightingsData['csv']['event'])
            );
        }
        if (!empty($delegationRequest)) {
            if ($isSiteAdmin || $me['org_id'] == $delegationRequest['EventDelegation']['org_id']) {
                if ($isSiteAdmin) {
                    $message = sprintf(
                        __('%s has requested that %s take over this event.'),
                        h($delegationRequest['RequesterOrg']['name']),
                        h($delegationRequest['Org']['name'])
                    );
                } else {
                    $message = sprintf(
                        __('%s has requested that you take over this event.'),
                        h($delegationRequest['RequesterOrg']['name'])
                    );
                }
            } else {
                $message = sprintf(
                    __('You have requested that %s take over this event.'),
                    h($delegationRequest['Org']['name'])
                );
            }
            $table_data[] = array(
                'key' => __('Delegation request'),
                'class' => 'background-red bold',
                'html' => sprintf(
                    '%s (%s)',
                    $message,
                    sprintf (
                        '<a href="#" style="color:white;" onClick="genericPopup(%s);">%s</a>',
                        sprintf(
                            "'%s/eventDelegations/view/%s', '#confirmation_box'",
                            $baseurl,
                            h($delegationRequest['EventDelegation']['id'])
                        ),
                        __('View request details')
                    )
                )
            );
            if (!Configure::read('MISP.completely_disable_correlation') && Configure::read('MISP.allow_disabling_correlation')) {
                $table_data[] = array(
                    'key' => __('Correlation'),
                    'class' => $event['Event']['disable_correlation'] ? 'background-red bold' : '',
                    'html' => sprintf(
                        '%s%s',
                        $event['Event']['disable_correlation'] ? __('Disabled') : __('Enabled'),
                        (!$mayModify && !$isSiteAdmin) ? '' : sprintf(
                            sprintf(
                                ' (<a onClick="getPopup(%s);" style="%scursor:pointer;font-weight:normal;">%s</a>)',
                                sprintf(
                                    "'%s', 'events', 'toggleCorrelation', '', '#confirmation_box'",
                                    h($event['Event']['id'])
                                ),
                                $event['Event']['disable_correlation'] ? 'color:white;' : '',
                                $event['Event']['disable_correlation'] ? __('enable') : __('disable')
                            )
                        )
                    )
                );
            }
        }

    ?>
    <div class="row-fluid">
        <div class="span8">
            <h2 class="ellipsis-overflow"><?php echo ($extended ? '[' . __('Extended view') . '] ' : '') . nl2br($title); ?></h2>
            <?php echo $this->element('genericElements/viewMetaTable', array('table_data' => $table_data)); ?>
        </div>
        <div class="related span4">

            <?php if (!empty($warningTagConflicts)): ?>
                <div class="warning_container" style="width:80%;">
                    <h4 class="red"><?php echo __('Warning: Taxonomy inconsistencies');?></h4>
                    <?php echo '<ul>'; ?>
                    <?php
                        foreach ($warningTagConflicts as $taxonomy) {
                            echo sprintf('<li><a href="%s/taxonomies/view/%s" title="">%s</a></li>', $baseurl, h($taxonomy['Taxonomy']['id']), h($taxonomy['Taxonomy']['namespace']), h($taxonomy['Taxonomy']['description']));
                            echo '<ul>';
                            if ($taxonomy['Taxonomy']['exclusive']) {
                                echo sprintf(
                                    '<li>%s</li>', 
                                    sprintf(
                                        ('%s is an exclusive taxonomy. Only one Tag of this taxonomy is allowed on an element.'),
                                        sprintf('<strong>%s</strong>', h($taxonomy['Taxonomy']['namespace']))
                                    )
                                );
                            } else {
                                foreach ($taxonomy['TaxonomyPredicate'] as $predicate) {
                                    echo sprintf(
                                        '<li>%s</li>', 
                                        sprintf(
                                            ('%s is an exclusive taxonomy predicate. Only one Tag of this predicate is allowed on an element'),
                                            sprintf('<strong>%s</strong>', h($predicate['value']))
                                        )
                                    );
                                }
                            }
                            echo '</ul>';
                        }
                    ?>
                    <?php echo '</ul>' ?>
                </div>
            <?php endif; ?>

            <?php
                if (!empty($event['RelatedEvent'])):
            ?>
                    <h3><?php echo __('Related Events');?></h3>
                    <div class="inline correlation-container">
                        <?php
                            $count = 0;
                            $display_threshold = 10;
                            $total = count($event['RelatedEvent']);
                            foreach ($event['RelatedEvent'] as $relatedEvent):
                                $count++;
                                if ($count == $display_threshold+1 && $total > $display_threshold):
                                    ?>
                                        <div class="no-side-padding correlation-expand-button useCursorPointer linkButton blue"><?php echo __('Show (%s more)', $total - $count);?></div>
                                    <?php
                                endif;
                        ?>
                            <?php
                                echo $this->element('/Events/View/related_event', array(
                                    'related' => $relatedEvent['Event'],
                                    'color_red' => $relatedEvent['Event']['orgc_id'] == $me['org_id'],
                                    'hide' => $count > $display_threshold,
                                    'relatedEventCorrelationCount' => $relatedEventCorrelationCount,
                                    'from_id' => $event['Event']['id']
                                ));
                            ?>
                        <?php
                            endforeach;
                            if ($total > $display_threshold):
                        ?>
                            <div class="no-side-padding correlation-collapse-button useCursorPointer linkButton blue" style="display:none;"><?php echo __('Collapse…');?></div>
                        <?php
                            endif;
                        ?>
                    </div>
            <?php
                endif;
                if (!empty($event['Feed']) || !empty($event['Event']['FeedCount'])):
            ?>
                    <h3>Related Feeds</h3>
            <?php
                    if (!empty($event['Feed'])):
            ?>
            <div class="correlation-container">
                <?php
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
                <?php endforeach; ?>
            </div>
                <?php
                    elseif (!empty($event['Event']['FeedCount'])):
                ?>
                        <span>
                            <?php echo __('This event has ');?><span class="bold"><?php echo h($event['Event']['FeedCount']); ?></span>
                            <?php echo __('correlations with data contained within the various feeds, however, due to the large number of attributes the actual feed correlations are not shown. Click <a href="%s\/overrideLimit:1">here</a> to refresh the page with the feed data loaded.', h($this->here));?>
                     </span>
                <?php
                    endif;
                endif;
                if (!empty($event['Server']) || !empty($event['Event']['ServerCount'])):
            ?>
                    <h3>Related Server</h3>
            <?php
                    if (!empty($event['Server'])):
            ?>
                    <div class="correlation-container" style="margin-bottom: 15px;">
            <?php
                        foreach ($event['Server'] as $relatedServer):
                            if (empty($relatedServer['id'])) {
                                continue;
                            }
                            $relatedData = array('Name' => $relatedServer['name'], 'URL' => $relatedServer['url']);
                            $popover = '';
                            foreach ($relatedData as $k => $v) {
                                $popover .= '<span class=\'bold\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
                            }
                ?>
                                <span style="white-space: nowrap; display: inline-block">
                                    <a href="<?php echo $baseurl; ?>/servers/previewIndex/<?php echo h($relatedServer['id']); ?>" class="linkButton useCursorPointer" data-toggle="popover" data-content="<?php echo h($popover); ?>" data-trigger="hover"><?php echo h($relatedServer['name']) . ' (' . $relatedServer['id'] . ')'; ?></a>&nbsp;
                                </span>
                <?php
                        endforeach;
                ?>
                    </div>
                <?php
                    elseif (!empty($event['Event']['FeedCount'])):
                ?>
                        <span>
                            <?php echo __('This event has ');?><span class="bold"><?php echo h($event['Event']['FeedCount']); ?></span>
                            <?php echo __('correlations with data contained within the various feeds, however, due to the large number of attributes the actual feed correlations are not shown. Click <a href="%s\/overrideLimit:1">here</a> to refresh the page with the feed data loaded.', h($this->here));?>
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
        <button class="btn btn-inverse toggle qet galaxy-toggle-button" id="eventtimeline_toggle" data-toggle-type="eventtimeline" onclick="enable_timeline();">
            <span class="icon-plus icon-white" title="<?php echo __('Toggle Event timeline');?>" role="button" tabindex="0" aria-label="<?php echo __('Toggle Event timeline');?>" style="vertical-align:top;"></span><?php echo __('Event timeline');?>
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
    <div id="eventtimeline_div" class="info_container_eventtimeline" style="display: none;" data-fullscreen="false">
        <?php echo $this->element('view_timeline'); ?>
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
    $.get("/events/viewGalaxyMatrix/<?php echo h($event['Event']['id']); ?>/<?php echo h($mitreAttackGalaxyId); ?>/event/1", function(data) {
        $("#attackmatrix_div").html(data);
    });
}
</script>
<input type="hidden" value="/shortcuts/event_view.json" class="keyboardShortcutsConfig" />
