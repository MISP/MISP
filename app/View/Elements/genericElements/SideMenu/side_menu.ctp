<?php
$this->set('menuItem', $menuItem);
$divider = '<li class="divider"></li>';
?>
<div class="actions sideMenu">
    <ul class="nav nav-list">
        <?php
            switch ($menuList) {
                case 'dashboard':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'dashboardIndex',
                        'url' => $baseurl . '/dashboards',
                        'text' => __('View Dashboard')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'dashboardAdd',
                        'text' => __('Add Widget'),
                        'onClick' => array(
                            'function' => 'openGenericModalPost',
                            'params' => array($baseurl . '/dashboards/getForm/add')
                        ),
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'dashboardImport',
                        'text' => __('Import Config JSON'),
                        'url' => $baseurl . '/dashboards/import',
                        'link_class' => 'modal-open',
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'dashboardExport',
                        'text' => __('Export Config JSON'),
                        'url' => $baseurl . '/dashboards/export',
                        'link_class' => 'modal-open',
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'dashboardSave',
                        'text' => __('Save Dashboard Config'),
                        'url' => $baseurl . '/dashboards/saveTemplate',
                        'link_class' => 'modal-open',
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'dashboardTemplateIndex',
                        'url' => $baseurl . '/dashboards/listTemplates',
                        'text' => __('List Dashboard Templates')
                    ));
                    break;
                case 'event':
                    $eventId = (int)$event['Event']['id'];
                    echo '<div id="hiddenSideMenuData" class="hidden" data-event-id="' . $eventId . '"></div>';
                    $mayModify = $mayModify ?? $this->Acl->canModifyEvent($event);
                    $mayPublish = $mayPublish ?? ($mayModify && $this->Acl->canPublishEvent($event));

                    if ($menuItem === 'template_populate_results') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'template_populate_results',
                            'url' => $baseurl . '/templates/index',
                            'text' => __('Populate From Template')
                        ));
                    } else if ($menuItem === 'enrichmentResults') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'enrichmentResults',
                            'text' => __('Enrichment Module Result')
                        ));
                        echo $divider;
                    } else if ($menuItem === 'freetextResults') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'freetextResults',
                            'text' => __('Freetext Import Result')
                        ));
                        echo $divider;
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewEvent',
                        'url' => $baseurl . '/events/view/' . $eventId,
                        'text' => __('View Event')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewGraph',
                        'url' => $baseurl . '/events/viewGraph/' . $eventId,
                        'text' => __('View Correlation Graph')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'eventLog',
                        'url' => $baseurl . (Configure::read('MISP.log_new_audit') ? '/audit_logs/eventIndex/' : '/logs/event_index/') . $eventId,
                        'text' => __('View Event History')
                    ));
                    echo $divider;
                    if ($isSiteAdmin || $mayModify) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editEvent',
                            'url' => $baseurl . '/events/edit/' . $eventId,
                            'text' => __('Edit Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/events/delete/' . $eventId,
                            'text' => __('Delete Event'),
                            'onClick' => array(
                                'function' => 'deleteEventPopup',
                                'params' => [$eventId]
                            ),
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addAttribute',
                            'url' => $baseurl . '/attributes/add/' . $eventId,
                            'text' => __('Add Attribute')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addObject',
                            'text' => __('Add Object'),
                            'onClick' => array(
                                'function' => 'popoverPopup',
                                'params' => array('this', $eventId, 'objectTemplates', 'objectMetaChoice')
                            ),
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addAttachment',
                            'url' => $baseurl . '/attributes/add_attachment/' . $eventId,
                            'text' => __('Add Attachment')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => '/eventReports/add/' . $eventId,
                            'text' => __('Add Event Report')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'populateFrom',
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array($eventId, 'events', 'importChoice')
                            ),
                            'text' => __('Populate from…')
                        ));
                        if ($menuItem === 'populateFromtemplate') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'populateFromtemplate',
                                'url' => $baseurl . '/templates/populateEventFromTemplate/' . $template_id . '/' . $eventId,
                                'text' => __('Populate From Template')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'genericPopup',
                                'params' => array($baseurl . '/events/enrichEvent/' . $eventId, '#confirmation_box')
                            ),
                            'text' => __('Enrich Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'merge',
                            'url' => $baseurl . '/events/merge/' . $eventId,
                            'text' => __('Merge attributes from…')
                        ));
                    }
                    if ($this->Acl->canAccess('shadowAttributes', 'add') && (($isSiteAdmin && (!isset($mayModify) || !$mayModify)) || (!isset($mayModify) || !$mayModify))) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'proposeAttribute',
                            'url' => $baseurl . '/shadow_attributes/add/' . $eventId,
                            'text' => __('Propose Attribute')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'proposeAttachment',
                            'url' => $baseurl . '/shadow_attributes/add_attachment/' . $eventId,
                            'text' => __('Propose Attachment')
                        ));
                    }
                    echo $divider;
                    if ($isSiteAdmin || $mayPublish) {
                        echo '<div id="hiddenSideMenuData" class="hidden" data-event-id="' . $eventId . '"></div>';
                        $isPublished = isset($event['Event']['published']) && 0 == $event['Event']['published'];
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'publishPopup',
                                'params' => array($eventId, 'alert')
                            ),
                            'class' => 'publishButtons not-published' . ($isPublished ? '' : ' hidden'),
                            'text' => __('Publish Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'publishPopup',
                                'params' => array($eventId, 'publish')
                            ),
                            'class' => 'publishButtons not-published' . ($isPublished ? '' : ' hidden'),
                            'text' => __('Publish (no email)')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'publishPopup',
                                'params' => array($eventId, 'unpublish')
                            ),
                            'class' => (isset($event['Event']['published']) && (1 == $event['Event']['published'] && $mayModify)) ? '' : 'hidden',
                            'text' => __('Unpublish')
                        ));
                    }
                    if (!empty($event['Event']['published']) && $me['Role']['perm_sighting']) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'publishPopup',
                                'params' => array($eventId, 'sighting')
                            ),
                            'class' => 'publishButtons',
                            'text' => __('Publish Sightings')
                        ));
                    }
                    if (Configure::read('MISP.delegation')) {
                        if ((Configure::read('MISP.unpublishedprivate') || (isset($event['Event']['distribution']) && $event['Event']['distribution'] == 0)) && (!isset($delegationRequest) || !$delegationRequest) && ($isSiteAdmin || (isset($isAclDelegate) && $isAclDelegate))) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'delegatePopup',
                                    'params' => array($eventId)
                                ),
                                'text' => __('Delegate Publishing')
                            ));
                        }
                        if (isset($delegationRequest) && $delegationRequest && ($isSiteAdmin || ($isAclPublish && ($me['org_id'] == $delegationRequest['EventDelegation']['org_id'] || $me['org_id'] == $delegationRequest['EventDelegation']['requester_org_id'])))) {
                            echo $divider;
                            if ($isSiteAdmin || ($isAclPublish && ($me['org_id'] == $delegationRequest['EventDelegation']['org_id']))) {
                                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                    'onClick' => array(
                                        'function' => 'genericPopup',
                                        'params' => array($baseurl . '/event_delegations/acceptDelegation/' . $delegationRequest['EventDelegation']['id'], '#confirmation_box')
                                    ),
                                    'text' => __('Accept Delegation Request')
                                ));
                            }
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'genericPopup',
                                    'params' => array($baseurl . '/event_delegations/deleteDelegation/' . $delegationRequest['EventDelegation']['id'], '#confirmation_box')
                                ),
                                'text' => __('Discard Delegation Request')
                            ));
                            echo $divider;
                        }
                    }
                    if ($this->Acl->canAccess('events', 'pushEventToZMQ') && Configure::read('Plugin.ZeroMQ_enable')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/events/pushEventToZMQ/' . $eventId,
                            'text' => __('Publish event to ZMQ'),
                            'message' => __('Are you sure you wish to republish the current event to the ZMQ channel?')
                        ));
                    }
                    if ($this->Acl->canAccess('events', 'pushEventToKafka') &&
                        Configure::read('Plugin.Kafka_enable') &&
                        Configure::read('Plugin.Kafka_event_notifications_enable') &&
                        Configure::read('Plugin.Kafka_event_notifications_topic')
                    ) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/events/pushEventToKafka/' . $eventId,
                            'text' => __('Publish event to Kafka'),
                            'message' => __('Are you sure you wish to republish the current event to the Kafka topic?')
                        ));
                    }
                    if (!empty($event['Orgc']['local'])) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'contact',
                            'url' => $baseurl . '/events/contact/' . $eventId,
                            'text' => __('Contact Reporter')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'getPopup',
                            'params' => array($eventId, 'events', 'exportChoice')
                        ),
                        'text' => __('Download as…')
                    ));
                    echo $divider;
                    if ($me['Role']['perm_modify']) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'openGenericModal',
                                'params' => [
                                    sprintf(
                                        '%s/collectionElements/addElementToCollection/Event/%s',
                                        $baseurl,
                                        h($event['Event']['uuid'])
                                    )
                                ]
                            ),
                            'text' => __('Add Event to Collection')
                        ));
                        echo $divider;
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/events/index',
                        'text' => __('List Events')
                    ));
                    if ($this->Acl->canAccess('events', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/events/add',
                            'text' => __('Add Event')
                        ));
                    }
                break;

                case 'event_restsearch_export':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/events/index',
                        'text' => __('List Events')
                    ));
                    break;

                case 'tag-collections':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/tag_collections/index',
                        'text' => __('List Tag Collections')
                    ));
                    if ($this->Acl->canAccess('tag_collections', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/tag_collections/add',
                            'text' => __('Add Tag Collection')
                        ));
                        if ($menuItem === 'edit') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/tag_collections/edit/' . $id,
                                'text' => __('Add Tag Collection')
                            ));
                        }
                    }
                    echo sprintf(
                        '<li id="liexport"><a href="%s/tag_collections/index.json" download="tag_collections_all.json">%s</a></li>',
                        $baseurl,
                        __('Export Tag Collections')
                    );
                    if ($this->Acl->canAccess('tagCollections', 'import')) {
                        echo sprintf(
                            '<li id="liimport"><a href="%s/tag_collections/import">%s</a></li>',
                            $baseurl,
                            __('Import Tag Collections')
                        );
                    }
                    break;
                case 'collections':
                    if ($menuItem === 'edit' || $menuItem === 'view') {
                        if ($this->Acl->canAccess('collections', 'add') && $mayModify) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', [
                                'element_id' => 'edit',
                                'url' => $baseurl . '/collections/edit/' . h($id),
                                'text' => __('Edit Collection')
                            ]);
                            echo $this->element('/genericElements/SideMenu/side_menu_link', [
                                'element_id' => 'delete',
                                'onClick' => [
                                    'function' => 'openGenericModal',
                                    'params' => array($baseurl . '/Collections/delete/' . h($id))
                                ],
                                'text' => __('Delete Collection')
                            ]);
                            echo $this->element('/genericElements/SideMenu/side_menu_link', [
                                'text' => __('Add Element to Collection'),
                                'onClick' => [
                                    'function' => 'openGenericModal',
                                    'params' => array($baseurl . '/CollectionElements/add/' . h($id))
                                ],
                            ]);
                            echo $divider;
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/collections/view/' . h($id),
                            'text' => __('View Collection')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => $baseurl . '/collections/index',
                        'text' => __('List Collections')
                    ));
                    if ($this->Acl->canAccess('collections', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => $baseurl . '/collections/add',
                            'text' => __('Add Collection')
                        ));
                    }
                    break;
                case 'event-collection':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => $baseurl . '/events/index',
                        'text' => __('List Events')
                    ));
                    if ($this->Acl->canAccess('events', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => $baseurl . '/events/add',
                            'text' => __('Add Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'import_from',
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array('0', 'events', 'importChoice/event-collection')
                            ),
                            'text' => __('Import from…')
                        ));
                        if ($this->Acl->canAccess('api', 'rest')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'rest',
                                'url' => $baseurl . '/api/rest',
                                'text' => __('REST client')
                            ));
                        }
                    }
                    echo $divider;
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'listAttributes',
                        'url' => $baseurl . '/attributes/index',
                        'text' => __('List Attributes')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'searchAttributes',
                        'url' => $baseurl . '/attributes/search',
                        'text' => __('Search Attributes')
                    ));
                    echo $divider;
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewProposals',
                        'url' => $baseurl . '/shadow_attributes/index/all:0',
                        'text' => __('View Proposals')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewProposalIndex',
                        'url' => $baseurl . '/events/proposalEventIndex',
                        'text' => __('Events with proposals')
                    ));
                    if ($this->Acl->canAccess('eventDelegations', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewDelegations',
                            'url' => $baseurl . '/event_delegations/index/context:pending',
                            'text' => __('View delegation requests')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewPeriodicSummary',
                        'url' => $baseurl . '/users/viewPeriodicSummary/daily',
                        'text' => __('View periodic summary')
                    ));
                    if ($menuItem === 'viewPeriodicSummary' || $menuItem === 'notification_settings') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'notification_settings',
                            'url' => $baseurl . '/users/notificationSettings',
                            'text' => __('Periodic summary settings')
                        ));
                    }
                    echo $divider;
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/events/export',
                        'text' => __('Export')
                    ));
                    if ($this->Acl->canAccess('events', 'automation')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'automation',
                            'url' => $baseurl . '/events/automation',
                            'text' => __('Automation')
                        ));
                    }
                    if (!$isSiteAdmin && $hostOrgUser) {
                        echo $divider;
                        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'eventBlocklistsAdd',
                                'url' => $baseurl . '/eventBlocklists/add',
                                'text' => __('Blocklists Event')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'eventBlocklists',
                                'url' => $baseurl . '/eventBlocklists',
                                'text' => __('Manage Event Blocklists')
                            ));
                        }
                    }
                break;

                case 'eventReports':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/eventReports/index',
                        'text' => __('List Event Reports')
                    ));
                    if ($this->Acl->canAccess('eventReports', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'text' => __('Add Event Report'),
                            'title' => __('Add Event Report'),
                            'onClick' => array(
                                'function' => 'openIdSelection',
                                'params' => array('this', 'eventReports', 'add')
                            ),
                        ));
                    }
                    if ($menuItem === 'view' || $menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => '/eventReports/view/' . h($id),
                            'text' => __('View Event Report')
                        ));
                        if ($canEdit) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => '/eventReports/edit/' . h($id),
                                'text' => __('Edit Event Report'),
                            ));
                        }
                        if (Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => '/admin/audit_logs/index/model:EventReport/model_id:' . h($id),
                                'text' => __('View report history'),
                            ));
                        }
                    }
                    break;

                case 'regexp':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => sprintf(
                            '%s%s/regexp/index',
                            $baseurl,
                            $isSiteAdmin ? '/admin' : ''
                        ),
                        'text' => __('List Regexp')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/admin/regexp/add',
                            'text' => __('New Regexp')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/admin/regexp/clean',
                            'text' => __('Perform on existing'),
                            'message' => __('Are you sure you want to rerun all of the regex rules on every attribute in the database? This task will take a long while and will modify data indiscriminately based on the rules configured.')
                        ));
                    }
                    if ($menuItem === 'edit') {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/admin/regexp/edit/' . h($id),
                            'text' => __('Edit Regexp')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/admin/regexp/delete/' . h($id),
                            'text' => __('Delete Regexp'),
                            'message' => __('Are you sure you want to delete #%s?', h($id))
                        ));
                    }
                break;

                case 'correlationRules':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => $baseurl . '/correlationRules/index',
                        'text' => __('Correlation Rules')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'add',
                        'url' => $baseurl . '/correlationRules/add',
                        'text' => __('Add Correlation Rule')
                    ));
                    break;

                case 'correlationExclusions':
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'text' => __('View Correlation Exclusion')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => $baseurl . '/correlation_exclusions/index',
                        'text' => __('List Correlation Exclusions')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'add',
                        'url' => $baseurl . '/correlation_exclusions/add',
                        'text' => __('Add Correlation Exclusion')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'top',
                        'url' => $baseurl . '/correlations/top',
                        'text' => __('Top Correlations')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'over',
                        'url' => $baseurl . '/correlations/overCorrelations',
                        'text' => __('Over-correlating Values')
                    ));
                    break;

                case 'warninglist':
                    if ($menuItem === 'view' || $menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/warninglists/view/' . h($id),
                            'text' => __('View Warninglist')
                        ));
                        if (!$isDefault && $this->Acl->canAccess('warninglists', 'edit')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', [
                                'element_id' => 'edit',
                                'url' => $baseurl . '/warninglists/edit/' . h($id),
                                'text' => __('Edit Warninglist'),
                            ]);
                        }
                    }
                    if ($this->Acl->canAccess('warninglists', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', [
                            'element_id' => 'add',
                            'url' => $baseurl . '/warninglists/add',
                            'text' => __('Add Warninglist'),
                        ]);
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/warninglists/index',
                        'text' => __('List Warninglists')
                    ));

                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/warninglists/update',
                            'text' => __('Update Warninglists'),
                            'message' => __('Are you sure you want to update all warninglists?')
                        ));
                    }

                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'check_value',
                        'url' => $baseurl . '/warninglists/checkValue',
                        'text' => __('Search in Warninglists')
                    ));
                    break;

                case 'noticelist':
                    if ($menuItem === 'view_noticelist') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view_noticelist',
                            'text' => __('View Noticelist')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'list_noticelists',
                        'url' => $baseurl . '/noticelists/index',
                        'text' => __('List Noticelist')
                    ));
                    if ($this->Acl->canAccess('noticelists', 'update')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'element_id' => 'update_noticelists',
                            'url' => $baseurl . '/noticelists/update',
                            'text' => __('Update Noticelists'),
                            'message' => __('Do you wish to continue and update all noticelists?')
                        ));
                    }
                    break;

                case 'allowedlist':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => sprintf(
                            '%s%s/allowedlists/index',
                            $baseurl,
                            $isSiteAdmin ? '/admin' : ''
                        ),
                        'text' => __('List Allowedlist')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/admin/allowedlists/add',
                            'text' => __('New Allowedlist')
                        ));
                    }
                    if ($menuItem == 'edit') {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/admin/allowedlists/edit/' . h($id),
                            'element_id' => 'edit',
                            'text' => __('Edit Allowedlist')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/admin/allowedlists/delete/' . h($id),
                            'text' => __('Delete Allowedlist'),
                            'message' => __('Are you sure you want to delete #%s?', h($id))
                        ));
                    }
                    break;

                case 'globalActions':
                    if ($menuItem === 'edit' || $menuItem === 'view' || $menuItem === 'change_pw') {
                        if ($this->Acl->canAccess('users', 'edit')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/users/edit',
                                'text' => __('Edit My Profile')
                            ));
                        }
                        if ($this->Acl->canAccess('users', 'change_pw')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/users/change_pw',
                                'text' => __('Change Password')
                            ));
                        } else if (Configure::read('Plugin.CustomAuth_custom_password_reset')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'custom_pw_reset',
                                'url' => Configure::read('Plugin.CustomAuth_custom_password_reset'),
                                'text' => __('Change Password')
                            ));
                        }
                        echo $divider;
                    }

                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'view',
                        'url' => $baseurl . '/users/view/me',
                        'text' => __('My Profile')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'user_settings_index_me',
                        'url' => $baseurl . '/user_settings/index/user_id:me',
                        'text' => __('My Settings')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'notification_settings',
                        'url' => $baseurl . '/users/notificationSettings',
                        'text' => __('Periodic summary settings')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'user_settings_set',
                        'url' => $baseurl . '/user_settings/setSetting',
                        'text' => __('Set Setting')
                    ));
                    if ($this->Acl->canAccess('organisations', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexOrg',
                            'url' => $baseurl . '/organisations/index',
                            'text' => __('List Organisations')
                        ));
                    }
                    if ($menuItem === 'viewOrg') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewOrg',
                            'url' => $baseurl . '/organisations/view/' . h($id),
                            'text' => __('View Organisation')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'roles',
                        'url' => $baseurl . '/roles/index',
                        'text' => __('Role Permissions')
                    ));
                    if ($menuItem === 'editSG' || ($menuItem == 'viewSG' && $mayModify)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editSG',
                            'url' => $baseurl . '/sharing_groups/edit/' . h($id),
                            'text' => __('Edit Sharing Group')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewSG',
                            'url' => $baseurl . '/sharing_groups/view/' . h($id),
                            'text' => __('View Sharing Group')
                        ));
                    }
                    if ($menuItem === 'editMG' || ($menuItem === 'viewMG' && $this->Acl->canAccess('sharing_group_blueprints', 'edit'))) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editMG',
                            'url' => $baseurl . '/sharing_group_blueprints/edit/' . h($id),
                            'text' => __('Edit Sharing Group Blueprint')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewMG',
                            'url' => $baseurl . '/sharing_group_blueprints/view/' . h($id),
                            'text' => __('View Sharing Group Blueprint')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'text' => __('Execute Sharing Group Blueprint'),
                            'onClick' => array(
                                'function' => 'openGenericModal',
                                'params' => array($baseurl . '/sharing_group_blueprints/execute/' . h($id))
                            ),
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'indexSG',
                        'url' => $baseurl . '/sharing_groups/index',
                        'text' => __('List Sharing Groups')
                    ));
                    if ($this->Acl->canAccess('sharing_groups', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addSG',
                            'url' => $baseurl . '/sharing_groups/add',
                            'text' => __('Add Sharing Group')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexMG',
                            'url' => $baseurl . '/sharing_group_blueprints/index',
                            'text' => __('List Sharing Group Blueprints')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addMG',
                            'url' => $baseurl . '/sharing_group_blueprints/add',
                            'text' => __('Add Sharing Group Blueprint')
                        ));
                    }
                    echo $divider;
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'categoriesAndTypes',
                        'url' => $baseurl . '/pages/display/doc/categories_and_types',
                        'text' => __('Categories & Types'),
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/users/terms',
                        'text' => __('Terms & Conditions')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/users/statistics',
                        'text' => __('Statistics')
                    ));
                    break;

                case 'sync':
                    if ($me['Role']['perm_sync']) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/createSync',
                            'text' => __('Create Sync Config')
                        ));
                    }
                    if ($menuItem === 'import' && ($me['Role']['perm_site_admin'])) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/import',
                            'text' => __('Import Server Settings')
                        ));
                    }
                    if ($menuItem === 'previewEvent' && ($isSiteAdmin || $hostOrg)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => sprintf(
                                '%s/servers/previewIndex/%s',
                                $baseurl,
                                h($server['Server']['id'])
                            ),
                            'text' => __('Explore Remote Server')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => sprintf(
                                '%s/servers/previewEvent/%s/%s',
                                $baseurl,
                                h($server['Server']['id']),
                                h($event['Event']['id'])
                            ),
                            'text' => __('Explore Remote Event')
                        ));
                    }
                    if ($menuItem === 'previewEvent' && $isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'pull',
                            'url' => sprintf(
                                '%s/servers/pull/%s/%s',
                                $baseurl,
                                h($server['Server']['id']),
                                h($event['Event']['id'])
                            ),
                            'text' => __('Fetch This Event'),
                            'message' => __('Are you sure you want to fetch and save this event on your instance?')
                        ));
                    }
                    if ($menuItem === 'previewIndex' && ($isSiteAdmin || $hostOrg)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'previewIndex',
                            'url' => sprintf(
                                '%s/servers/previewIndex/%s',
                                $baseurl,
                                h($id)
                            ),
                            'text' => __('Explore Remote Server')
                        ));
                    }
                    if ($menuItem === 'edit' && $isSiteAdmin) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => $baseurl . '/servers/edit/' . h($id),
                            'text' => __('Edit Server')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'pull',
                            'url' => sprintf(
                                '%s/servers/delete/%s',
                                $baseurl,
                                $this->Form->value('Server.id')
                            ),
                            'text' => __('Delete'),
                            'message' => __('Are you sure you want to delete #%s?', $this->Form->value('Server.id'))
                        ));
                    }
                    if ($this->Acl->canAccess('servers', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/index',
                            'text' => __('List Servers')
                        ));
                    }
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/add',
                            'text' => __('New Servers')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/compareServers',
                            'text' => __('Server overlap analysis matrix'),
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/communities/index',
                            'text' => __('List Communities'),
                            'element_id' => 'list_communities'
                        ));
                        if ($menuItem === 'view_community' || $menuItem === 'request_community_access') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'text' => __('Request Access'),
                                'url' => $baseurl . '/communities/requestAccess/' . h($community['uuid']),
                                'element_id' => 'request_community_access'
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'text' => __('View community'),
                                'url' => $baseurl . '/communities/view/' . h($community['uuid']),
                                'element_id' => 'view_community'

                            ));
                        }
                        if ($menuItem === 'view_email') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'text' => __('Request E-mail'),
                                'element_id' => 'view_email'
                            ));
                        }
                    }
                    if ($menuItem === 'id_translator') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'text' => __('Event ID translator'),
                            'url' => '/servers/idTranslator',
                            'element_id' => 'id_translator'
                        ));
                    }
                    echo $divider;
                    if ($this->Acl->canAccess('cerebrates', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/cerebrates/index',
                            'text' => __('List Cerebrates'),
                            'element_id' => 'list_cerebrates'
                        ));
                    }
                    if (in_array($menuItem, ['edit_cerebrate', 'view_cerebrate'])) {
                        if ($this->Acl->canAccess('cerebrates', 'view')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/cerebrates/view/' . h($id),
                                'text' => __('View Cerebrate'),
                                'element_id' => 'view_cerebrate'
                            ));
                        }
                        if ($this->Acl->canAccess('cerebrates', 'edit')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/cerebrates/edit/' . h($id),
                                'text' => __('Edit Cerebrate'),
                                'element_id' => 'edit_cerebrate'
                            ));
                        }
                    }
                    if (in_array($menuItem, ['add_cerebrate', 'edit_cerebrate', 'list_cerebrates', 'view_cerebrate'])  && $this->Acl->canAccess('cerebrates', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/cerebrates/add',
                            'text' => __('Add Cerebrate'),
                            'element_id' => 'add_cerebrates'
                        ));
                    }
                    break;

                case 'admin':
                    if ($menuItem === 'restore_deleted_events') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'restore_deleted_events',
                            'url' => $baseurl . '/events/restoreDeletedEvents',
                            'text' => __('Restore Deleted Events')
                        ));
                    }
                    if ($menuItem === 'editUser' || $menuItem === 'viewUser' || $menuItem === 'authKeyIndex') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewUser',
                            'url' => $baseurl . '/admin/users/view/' . h($id),
                            'text' => __('View User')
                        ));
                        if ($this->Acl->canAccess('users', 'initiatePasswordReset')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'initiatePasswordReset',
                                    'params' => array($id)
                                ),
                                'text' => __('Reset Password')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editUser',
                            'url' => $baseurl . '/admin/users/edit/' . h($id),
                            'text' => __('Edit User')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'deleteUser',
                            'url' => $baseurl . '/admin/users/delete/' . h($id),
                            'text' => __('Delete User'),
                            'message' => __('Are you sure you want to delete #%s? It is highly recommended to never delete users but to disable them instead.', h($id))
                        ));
                        echo $divider;
                    }
                    if ($isSiteAdmin && $menuItem === 'editRole') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editRole',
                            'url' => $baseurl . '/admin/roles/edit/' . h($id),
                            'text' => __('Edit Role')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'deleteRole',
                            'url' => $baseurl . '/admin/roles/delete/' . h($id),
                            'text' => __('Delete Role'),
                            'message' => __('Are you sure you want to delete #%s?', h($id))
                        ));
                        echo $divider;
                    }
                    if ($this->Acl->canAccess('users', 'admin_add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addUser',
                            'url' => $baseurl . '/admin/users/add',
                            'text' => __('Add User')
                        ));
                    }
                    if ($this->Acl->canAccess('users', 'admin_index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexUser',
                            'url' => $baseurl . '/admin/users/index',
                            'text' => __('List Users')
                        ));
                    }
                    if ($this->Acl->canAccess('users', 'registrations')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'registrations',
                            'url' => $baseurl . '/users/registrations',
                            'text' => __('Pending registrations')
                        ));
                    }
                    if ($isAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'user_settings_index',
                            'url' => $baseurl . '/user_settings/index/user_id:all',
                            'text' => __('User settings')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'user_settings_set',
                            'url' => $baseurl . '/user_settings/setSetting',
                            'text' => __('Set Setting')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'contact',
                            'url' => $baseurl . '/admin/users/email',
                            'text' => __('Contact Users')
                        ));
                    }
                    echo $divider;
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addOrg',
                            'url' => $baseurl . '/admin/organisations/add',
                            'text' => __('Add Organisation')
                        ));
                        if ($menuItem === 'editOrg' || $menuItem === 'viewOrg') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'editOrg',
                                'url' => $baseurl . '/admin/organisations/edit/' . h($id),
                                'text' => __('Edit Organisation')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'mergeOrg',
                                'onClick' => array(
                                    'function' => 'getPopup',
                                    'params' => array(h($id), 'organisations', 'merge', 'admin')
                                ),
                                'text' => __('Merge Organisation')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'viewOrg',
                                'url' => $baseurl . '/organisations/view/' . h($id),
                                'text' => __('View Organisation')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                                'url' => $baseurl . '/admin/organisations/delete/' . h($id),
                                'text' => __('Delete Organisation'),
                                'message' => __('Are you sure you want to delete #%s?', h($id))
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexOrg',
                            'url' => $baseurl . '/organisations/index',
                            'text' => __('List Organisations')
                        ));
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addRole',
                            'url' => $baseurl . '/admin/roles/add',
                            'text' => __('Add Role')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'indexRole',
                        'url' => $baseurl . '/roles/index',
                        'text' => __('List Roles')
                    ));
                    if ($isSiteAdmin) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/serverSettings',
                            'text' => __('Server Settings & Maintenance')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/servers/updateProgress',
                            'text' => __('Update Progress')
                        ));
                        if (Configure::read('Plugin.Benchmarking_enable')) {
                            echo $divider;
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/benchmarks/index',
                                'text' => __('Benchmarks')
                            ));
                        }
                        echo $divider;
                        if (Configure::read('MISP.background_jobs')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'jobs',
                                'url' => $baseurl . '/jobs/index',
                                'text' => __('Jobs')
                            ));
                            echo $divider;
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'tasks',
                                'url' => $baseurl . '/tasks',
                                'text' => __('Scheduled Tasks')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'eventBlockRule',
                            'url' => $baseurl . '/servers/eventBlockRule',
                            'text' => __('Event Block Rules')
                        ));
                        echo $divider;
                        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'eventBlocklistsAdd',
                                'url' => $baseurl . '/eventBlocklists/add',
                                'text' => __('Blocklists Event')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'eventBlocklists',
                                'url' => $baseurl . '/eventBlocklists',
                                'text' => __('Manage Event Blocklists')
                            ));
                            echo $divider;
                        }
                        if (!Configure::check('MISP.enableOrgBlocklisting') || Configure::read('MISP.enableOrgBlocklisting') !== false) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'orgBlocklistsAdd',
                                'url' => $baseurl . '/orgBlocklists/add',
                                'text' => __('Blocklists Organisation')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'orgBlocklists',
                                'url' => $baseurl . '/orgBlocklists',
                                'text' => __('Manage Org Blocklists')
                            ));
                            echo $divider;
                        }
                        if (!Configure::check('MISP.enableSightingBlocklisting') || Configure::read('MISP.enableSightingBlocklisting') !== false) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'sightingBlocklistsAdd',
                                'url' => $baseurl . '/sightingBlocklists/add',
                                'text' => __('Blocklists Sightings')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'sightingBlocklists',
                                'url' => $baseurl . '/sightingBlocklists',
                                'text' => __('Manage Sighting Blocklists')
                            ));
                            echo $divider;
                        }
                    }
                    break;

                case 'logs':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/logs/index',
                        'text' => __('Application Logs')
                    ));
                    if (Configure::read('MISP.log_new_audit') && $isAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'listAuditLogs',
                            'url' => $baseurl . '/admin/audit_logs/index',
                            'text' => __('Audit Logs'),
                        ));
                    }
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'listAccessLogs',
                            'url' => $baseurl . '/admin/access_logs/index',
                            'text' => __('Access Logs'),
                        ));
                    }
                    if ($isAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/admin/logs/search',
                            'text' => __('Search Logs')
                        ));
                    }
                    break;

                case 'threads':
                    if ($menuItem === 'add' || $menuItem === 'view') {
                        if (!(empty($thread_id) && empty($target_type))) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/threads/view/' . h($thread_id),
                                'text' => __('View Thread')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'add_post',
                                'url' => $baseurl . '/posts/add/thread/' . h($thread_id),
                                'text' => __('Add Post')
                            ));
                            echo $divider;
                        }
                    }
                    if ($menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/threads/view/' . h($thread_id),
                            'text' => __('View Thread')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => $baseurl . '/threads/view/' . h($id),
                            'text' => __('Edit Post')
                        ));
                        echo $divider;
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/threads/index',
                        'text' => __('List Threads')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/posts/add',
                        'text' => __('New Thread')
                    ));
                    break;

                case 'tags':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'indexfav',
                        'url' => $baseurl . '/tags/index/favouritesOnly:1',
                        'text' => __('List Favourite Tags')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/tags/index',
                        'text' => __('List Tags')
                    ));
                    if ($this->Acl->canAccess('tags', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/tags/add',
                            'text' => __('Add Tag')
                        ));
                    }
                    if ($menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'text' => __('Edit Tag')
                        ));
                    } elseif ($menuItem === 'viewGraph') {
                        if (!empty($taxonomy)) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'taxonomyview',
                                'url' => $baseurl . '/taxonomies/view/' . h($taxonomy['Taxonomy']['id']),
                                'text' => __('View Taxonomy')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewGraph',
                            'url' => $baseurl . '/tags/viewGraph/' . h($id),
                            'text' => __('View Correlation Graph')
                        ));
                    }
                break;

                case 'taxonomies':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/taxonomies/index',
                        'text' => __('List Taxonomies')
                    ));
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'text' => __('View Taxonomy')
                        ));
                        if ($this->Acl->canAccess('taxonomies', 'delete')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'delete',
                                'onClick' => array(
                                    'function' => 'deleteObject',
                                    'params' => array('taxonomies', 'delete', h($id))
                                ),
                                'text' => __('Delete Taxonomy')
                            ));
                        }
                    }
                    if ($this->Acl->canAccess('taxonomies', 'update')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'update',
                            'url' => $baseurl . '/taxonomies/update',
                            'text' => __('Update Taxonomies')
                        ));
                    }
                    break;

                case 'templates':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/templates/index',
                        'text' => __('List Templates')
                    ));
                    if ($this->Acl->canAccess('templates', 'add')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/templates/add',
                            'text' => __('Add Template')
                        ));
                    }
                    if ($menuItem === 'view' || $menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/templates/view/' . h($id),
                            'text' => __('View Template')
                        ));
                        if ($mayModify) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => $baseurl . '/templates/edit/' . h($id),
                                'text' => __('Edit Template')
                            ));
                        }
                    }
                    break;
                case 'decayingModel':
                    if ($isAdmin) {
                        if ($isSiteAdmin && ($menuItem === 'view' || $menuItem === 'index')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                                'event_id' => 'update',
                                'url' => $baseurl . '/decayingModel/update',
                                'text' => __('Update Default Models')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                                'event_id' => 'update',
                                'url' => $baseurl . '/decayingModel/update/true',
                                'text' => __('Force Update Default Models')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/decayingModel/import',
                            'text' => __('Import Decaying Model')
                        ));
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/decayingModel/add',
                            'text' => __('Add Decaying Model')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/decayingModel/decayingTool',
                            'text' => __('Decaying Models Tool')
                        ));
                        echo $divider;
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/decayingModel/index',
                        'text' => __('List Decaying Models')
                    ));
                    if (($menuItem === 'view' || $menuItem === 'edit')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/decayingModel/view/' . h($id),
                            'text' => __('View Decaying Model')
                        ));
                        if ($isSiteAdmin) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => $baseurl . '/decayingModel/edit/' . h($id),
                                'text' => __('Edit Decaying Model')
                            ));
                        }
                    }
                    break;

                case 'feeds':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/feeds/index',
                        'text' => __('List Feeds')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/feeds/searchCaches',
                        'text' => __('Search Feed Caches')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/feeds/add',
                            'text' => __('Add Feed')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'import',
                            'url' => $baseurl . '/feeds/importFeeds',
                            'text' => __('Import Feeds from JSON')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'compare',
                        'url' => $baseurl . '/feeds/compareFeeds',
                        'text' => __('Feed overlap analysis matrix')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'export',
                        'url' => $baseurl . '/feeds/index.json',
                        'text' => __('Export Feed settings'),
                        'download' => 'feed_index.json'
                    ));
                    if ($isSiteAdmin) {
                        if ($menuItem === 'edit' || $menuItem === 'view') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => $baseurl . '/feeds/edit/' . h($feedId),
                                'text' => __('Edit Feed')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'view',
                                'url' => $baseurl . '/feeds/view/' . h($feedId),
                                'text' => __('View Feed')
                            ));
                        } else if ($menuItem === 'previewIndex') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'previewIndex',
                                'url' => $baseurl . '/feeds/previewIndex/' . h($feed['Feed']['id']),
                                'text' => __('PreviewIndex')
                            ));
                        } else if ($menuItem === 'previewEvent') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'previewEvent',
                                'url' => $baseurl . '/feeds/previewEvent/' . h($feed['Feed']['id']) . '/' . h($id),
                                'text' => __('PreviewEvent')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                                'url' => sprintf(
                                    '%s/feeds/getEvent/%s/%s',
                                    $baseurl,
                                    h($feed['Feed']['id']),
                                    h($event['Event']['uuid'])
                                ),
                                'text' => __('Fetch This Event'),
                                'message' => __('Are you sure you want to fetch and save this event on your instance?')
                            ));
                        }
                    }
                break;

                case 'news':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/news/index',
                        'text' => __('View News'),
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/admin/news/index',
                            'text' => __('View News as Admin'),
                            'element_id' => 'admin_index',
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/news/add',
                            'text' => __('Add News Item')
                        ));
                        if ($menuItem === 'edit') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'text' => __('Edit News Item')
                            ));
                        }
                    }
                    break;

                case 'galaxies':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'galaxy_index',
                        'url' => $baseurl . '/galaxies/index',
                        'text' => __('List Galaxies')
                    ));
                    if ($this->Acl->canAccess('galaxy_cluster_blocklists', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'index_blocklist',
                            'url' => $baseurl . '/galaxy_cluster_blocklists/index',
                            'text' => __('List Cluster Blocklists')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'relationship_index',
                        'url' => $baseurl . '/galaxy_cluster_relations/index',
                        'text' => __('List Relationships')
                    ));
                    if ($isSiteAdmin) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'element_id' => 'update',
                            'url' => $baseurl . '/galaxies/update',
                            'text' => __('Update Galaxies'),
                            'message' => __('Are you sure you want to reimport all galaxies from the submodule?')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'element_id' => 'forceupdate',
                            'url' => $baseurl . '/galaxies/update/force:1',
                            'text' => __('Force Update Galaxies'),
                            'message' => __('Are you sure you want to drop and reimport all galaxies from the submodule?')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'element_id' => 'forceupdate',
                            'url' => $baseurl . '/galaxies/wipe_default',
                            'text' => __('Wipe Default Galaxy Clusters'),
                            'message' => __('Are you sure you want to drop all default galaxy clusters?')
                        ));
                    }
                    if ($this->Acl->canAccess('galaxies', 'import')) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/galaxies/import',
                            'text' => __('Import Galaxy Clusters')
                        ));
                    }
                    if ($menuItem === 'view' || $menuItem === 'export' || $menuItem === 'view_cluster' || $menuItem === 'add_cluster') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'export',
                            'url' => $baseurl . '/galaxies/export/' . h($galaxy['Galaxy']['id']),
                            'text' => __('Export Galaxy Clusters')
                        ));
                    }
                    if ($menuItem === 'viewGraph' || $menuItem === 'view_cluster' || $menuItem === 'update_cluster' || $menuItem === 'add_cluster' || $menuItem === 'edit_cluster') {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/galaxies/view/' . h($galaxy_id),
                            'text' => __('View Galaxy')
                        ));
                        if ($menuItem !== 'add_cluster') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'view_cluster',
                                'url' => $baseurl . '/galaxy_clusters/view/' . h($id),
                                'text' => __('View Cluster')
                            ));
                        }
                        if ($menuItem !== 'add_cluster' && $this->Acl->canModifyGalaxyCluster($cluster)) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit_cluster',
                                'url' => $baseurl . '/galaxy_clusters/edit/' . h($id),
                                'text' => __('Edit Cluster')
                            ));
                        }
                        if ($this->Acl->canAccess('galaxyClusters', 'add')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'add_cluster',
                                'url' => $baseurl . '/galaxy_clusters/add/' . h($galaxy_id),
                                'text' => __('Add Cluster')
                            ));
                        }
                        if ($menuItem !== 'add_cluster' && $this->Acl->canAccess('galaxyClusters', 'add')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/galaxy_clusters/add/' . h($galaxy_id) . '/forkUuid:' . h($cluster['GalaxyCluster']['uuid']),
                                'text' => __('Fork Cluster')
                            ));
                            if ($this->Acl->canPublishGalaxyCluster($cluster)) {
                                echo $divider;
                                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                    'onClick' => array(
                                        'function' => 'publishPopup',
                                        'params' => array($cluster['GalaxyCluster']['id'], ($cluster['GalaxyCluster']['published'] ? 'unpublish' : 'publish'), 'galaxy_clusters')
                                    ),
                                    'class' => 'publishButtons not-published ',
                                    'text' => $cluster['GalaxyCluster']['published'] ? __('Unpublish Cluster') : __('Publish Cluster')
                                ));
                            }
                        }
                        if ($menuItem !== 'add_cluster') {
                            echo $divider;
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'viewGraph',
                                'url' => $baseurl . '/galaxies/viewGraph/' . h($id),
                                'text' => __('View Correlation Graph')
                            ));
                        }
                        if ($me['Role']['perm_modify']) {
                            echo $divider;
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'openGenericModal',
                                    'params' => [
                                        sprintf(
                                            '%s/collectionElements/addElementToCollection/GalaxyCluster/%s',
                                            $baseurl,
                                            h($cluster['GalaxyCluster']['uuid'])
                                        )
                                    ]
                                ),
                                'text' => __('Add Cluster to Collection')
                            ));
                        }
                    }
                    if ($menuItem === 'view' || $menuItem === 'export') {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => $baseurl . '/galaxies/view/' . h($galaxy['Galaxy']['id']),
                            'text' => __('View Galaxy')
                        ));
                        if ($this->Acl->canAccess('galaxyClusters', 'add')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'add_cluster',
                                'url' => $baseurl . '/galaxy_clusters/add/' . h($galaxy['Galaxy']['id']),
                                'text' => __('Add Cluster')
                            ));
                        }
                    }
                    break;

                case 'galaxy_cluster':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/galaxies/index',
                        'text' => __('List Galaxies')
                    ));
                    echo $divider;
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'view',
                        'url' => $baseurl . '/galaxies/view/' . h($galaxy_id),
                        'text' => __('View Galaxy')
                    ));
                    if ($menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view_cluster',
                            'url' => $baseurl . '/galaxy_clusters/view/' . h($clusterId),
                            'text' => __('View Cluster')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewGraph',
                            'url' => $baseurl . '/galaxies/viewGraph/' . h($id),
                            'text' => __('View Correlation Graph')
                        ));
                    }
                    if ($menuItem === 'view') {
                        echo $divider;
                        if (
                            isset($cluster['GalaxyCluster']['published']) && !$cluster['GalaxyCluster']['published'] &&
                            $this->Acl->canPublishGalaxyCluster($cluster)
                        ) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'publishPopup',
                                    'params' => array($cluster['GalaxyCluster']['id'], 'alert')
                                ),
                                'class' => 'publishButtons not-published ' . $publishButtons,
                                'text' => __('Publish Cluster')
                            ));
                        }
                    }
                    break;

                case 'galaxy_cluster_relations':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'galaxy_index',
                        'url' => $baseurl . '/galaxies/index',
                        'text' => __('List Galaxies')
                    ));
                    if ($this->Acl->canAccess('galaxy_cluster_blocklists', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'index_blocklist',
                            'url' => $baseurl . '/galaxy_cluster_blocklists/index',
                            'text' => __('List Cluster Blocklists')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => $baseurl . '/galaxy_cluster_relations/index',
                        'text' => __('List Relationships')
                    ));
                    if ($this->Acl->canAccess('galaxy_cluster_relations', 'add')) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => $baseurl . '/galaxy_cluster_relations/add/',
                            'text' => __('Add Relationship')
                        ));
                    }
                    break;

                case 'objectTemplates':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/objectTemplates/index',
                        'text' => __('List Object Templates')
                    ));
                    if ($this->Acl->canAccess('objectTemplates', 'update')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => $baseurl . '/objectTemplates/update',
                            'text' => __('Update Objects')
                        ));
                    }
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'text' => __('View Object Template')
                        ));
                    }
                    break;

                case 'sightingdb':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => $baseurl . '/sightingdb/add',
                        'text' => __('Add SightingDB connection')
                    ));
                    if ($isSiteAdmin) {
                        if ($menuItem === 'edit') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => $baseurl . '/sightingdb/edit/' . $id,
                                'element_id' => 'editSightingDB',
                                'class' => 'active',
                                'text' => __('Edit SightingDB connection')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => $baseurl . '/sightingdb/index',
                            'text' => __('List SightingDB connections')
                        ));
                    }
                    break;

                case 'api':
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'openapi',
                            'url' => $baseurl . '/api/openapi',
                            'text' => __('OpenAPI')
                        ));
                        if ($this->Acl->canAccess('api', 'rest')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'rest',
                                'url' => $baseurl . '/api/rest',
                                'text' => __('REST client')
                            ));
                        }
                    break;

            case 'workflowBlueprints':
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'element_id' => 'index',
                    'url' => '/workflowBlueprints/index',
                    'text' => __('List Workflow Blueprints')
                ));
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'url' => $baseurl . '/workflowBlueprints/import',
                    'text' => __('Import Workflow Blueprints')
                ));
                if ($isSiteAdmin && ($menuItem === 'view' || $menuItem === 'index')) {
                    echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                        'url' => $baseurl . '/workflowBlueprints/update',
                        'text' => __('Update Default Blueprints')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                        'url' => $baseurl . '/workflowBlueprints/update/true',
                        'text' => __('Force Update Default Blueprints')
                    ));
                }
                if ($menuItem === 'view' || $menuItem === 'edit') {
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'view',
                        'url' => '/workflowBlueprints/view/' . h($id),
                        'text' => __('View Workflow Blueprint')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => '/workflowBlueprints/edit/' . h($id),
                            'text' => __('Edit Workflow Blueprint')
                        ));
                    }
                    if (Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/admin/audit_logs/index/model:WorkflowBlueprint/model_id:' . h($id),
                            'text' => __('View workflow blueprint history'),
                        ));
                    }
                }
                echo $divider;
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'element_id' => 'index_trigger',
                    'url' => '/workflows/triggers',
                    'text' => __('List Triggers')
                ));
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'element_id' => 'index_module',
                    'url' => '/workflows/moduleIndex',
                    'text' => __('List Modules')
                ));
                break;

            case 'workflows':
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'element_id' => 'index_trigger',
                    'url' => '/workflows/triggers',
                    'text' => __('List Triggers')
                ));
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'element_id' => 'index_module',
                    'url' => '/workflows/moduleIndex',
                    'text' => __('List Modules')
                ));
                echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                    'element_id' => 'index',
                    'url' => '/workflowBlueprints/index',
                    'text' => __('List Workflow Blueprints')
                ));
                if ($menuItem === 'view' || $menuItem === 'edit') {
                    echo $divider;
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'view',
                        'url' => '/workflows/view/' . h($id),
                        'text' => __('View Workflow')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => '/workflows/edit/' . h($id),
                            'text' => __('Edit Workflow')
                        ));
                    }
                    if (Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/admin/audit_logs/index/model:Workflow/model_id:' . h($id),
                            'text' => __('View workflow history'),
                        ));
                    }
                }
                break;

                case 'analyst_data':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/analystData/index',
                        'text' => __('List Analyst Data')
                    ));
                    if ($this->Acl->canAccess('analyst_data_blocklists', 'index')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'index_blocklist',
                            'url' => $baseurl . '/analyst_data_blocklists/index',
                            'text' => __('List Analyst-Data Blocklists')
                        ));
                    }
                    if ($this->Acl->canAccess('analyst_data', 'add')) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add_note',
                            'url' => sprintf('/analystData/add/Note'),
                            'text' => __('Add Analyst Note')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add_opinion',
                            'url' => sprintf('/analystData/add/Opinion'),
                            'text' => __('Add Analyst Opinion')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add_relationship',
                            'url' => sprintf('/analystData/add/Relationship'),
                            'text' => __('Add Analyst Relationship')
                        ));
                    }
                    if ($menuItem === 'view' || $menuItem === 'edit') {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => sprintf('/analystData/view/%s/%s', h($modelSelection), h($id)),
                            'text' => __('View Analyst Data')
                        ));
                        if ($isSiteAdmin) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => sprintf('/analystData/edit/%s/%s', h($modelSelection), h($id)),
                                'text' => __('Edit Analyst Data')
                            ));
                        }
                    }
                    break;

                case 'bookmarks':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/bookmarks/index',
                        'text' => __('List Bookmarks')
                    ));
                    if ($this->Acl->canAccess('bookmarks', 'add')) {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => sprintf('/bookmarks/add'),
                            'text' => __('Add Bookmark')
                        ));
                    }
                    if ($menuItem === 'view' || $menuItem === 'edit') {
                        echo $divider;
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => sprintf('/bookmarks/view/%s', h($id)),
                            'text' => __('View Bookmark')
                        ));
                        if ($isSiteAdmin) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => sprintf('/bookmarks/edit/%s', h($id)),
                                'text' => __('Edit Bookmark')
                            ));
                        }
                    }
                    break;
            }
        ?>
    </ul>
</div>
