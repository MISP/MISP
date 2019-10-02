<div class="actions sideMenu">
    <ul class="nav nav-list">
        <?php
            switch ($menuList) {
                case 'event':
                    $dataEventId = isset($event['Event']['id']) ? h($event['Event']['id']) : 0;
                    echo '<div id="hiddenSideMenuData" class="hidden" data-event-id="' . $dataEventId . '"></div>';
                    if (in_array($menuItem, array('addAttribute', 'addObject', 'addAttachment', 'addIOC', 'addThreatConnect', 'populateFromTemplate'))) {
                        // we can safely assume that mayModify is true if coming from these actions, as they require it in the controller and the user has already passed that check
                        $mayModify = true;
                        if ($isAclPublish) $mayPublish = true;
                    }
                    if (($menuItem === 'template_populate_results')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'template_populate_results',
                            'url' => '/templates/index',
                            'text' => __('Populate From Template')
                        ));
                    }
                    if ($menuItem === 'enrichmentResults') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'enrichmentResults',
                            'url' => '#',
                            'text' => __('Enrichment Module Result')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    }
                    if ($menuItem === 'freetextResults') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'freetextResults',
                            'url' => '#',
                            'text' => __('Freetext Import Result')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewEvent',
                        'url' => '/events/view/' .  $event['Event']['id'],
                        'text' => __('View Event')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewGraph',
                        'url' => '/events/viewGraph/' .  $event['Event']['id'],
                        'text' => __('View Correlation Graph')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'eventLog',
                        'url' => '/logs/event_index/' .  $event['Event']['id'],
                        'text' => __('View Event History')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    if ($isSiteAdmin || (isset($mayModify) && $mayModify)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editEvent',
                            'url' => '/events/edit/' .  $event['Event']['id'],
                            'text' => __('Edit Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/events/delete/' . h($event['Event']['id']),
                            'text' => __('Delete Event'),
                            'message' => __('Are you sure you want to delete # %s?', h($event['Event']['id']))
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addAttribute',
                            'url' => '/attributes/add/' .  $event['Event']['id'],
                            'text' => __('Add Attribute')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addObject',
                            'text' => __('Add Object'),
                            'onClick' => array(
                                'function' => 'popoverPopup',
                                'params' => array('this', h($event['Event']['id']), 'objectTemplates', 'objectMetaChoice')
                            ),
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addAttachment',
                            'url' => '/attributes/add_attachment/' .  $event['Event']['id'],
                            'text' => __('Add Attachment')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array($event['Event']['id'], 'events', 'importChoice')
                            ),
                            'text' => __('Populate from...')
                        ));
                        if ($menuItem === 'populateFromtemplate') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => '/templates/populateEventFromTemplate/' . $template_id . '/' .  $event['Event']['id'],
                                'text' => __('Populate From Template')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'genericPopup',
                                'params' => array($baseurl . '/events/enrichEvent/' . $event['Event']['id'], '#confirmation_box')
                            ),
                            'text' => __('Enrich Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'merge',
                            'url' => '/events/merge/' . $event['Event']['id'],
                            'text' => __('Merge attributes from...')
                        ));
                    }
                    if (($isSiteAdmin && (!isset($mayModify) || !$mayModify)) || (!isset($mayModify) || !$mayModify)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'proposeAttribute',
                            'url' => '/shadow_attributes/add/' . $event['Event']['id'],
                            'text' => __('Propose Attribute')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'proposeAttachment',
                            'url' => '/shadow_attributes/add_attachment/' . $event['Event']['id'],
                            'text' => __('Propose Attachment')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    $publishButtons = ' hidden';
                    if (isset($event['Event']['published']) && 0 == $event['Event']['published'] && ($isSiteAdmin || (isset($mayPublish) && $mayPublish))) $publishButtons = "";
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'publishPopup',
                            'params' => array($event['Event']['id'], 'alert')
                        ),
                        'class' => 'publishButtons not-published ' . $publishButtons,
                        'text' => __('Publish Event')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'publishPopup',
                            'params' => array($event['Event']['id'], 'publish')
                        ),
                        'class' => 'publishButtons not-published ' . $publishButtons,
                        'text' => __('Publish (no email)')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'publishPopup',
                            'params' => array($event['Event']['id'], 'unpublish')
                        ),
                        'class' => (isset($event['Event']['published']) && (1 == $event['Event']['published'] && $mayModify)) ? '' : 'hidden',
                        'text' => __('Unpublish')
                    ));
                    if (Configure::read('MISP.delegation')) {
                        if ((Configure::read('MISP.unpublishedprivate') || (isset($event['Event']['distribution']) && $event['Event']['distribution'] == 0)) && (!isset($delegationRequest) || !$delegationRequest) && ($isSiteAdmin || (isset($isAclDelegate) && $isAclDelegate))) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'delegatePopup',
                                    'params' => array($event['Event']['id'])
                                ),
                                'text' => __('Delegate Publishing')
                            ));
                        }
                        if (isset($delegationRequest) && $delegationRequest && ($isSiteAdmin || ($isAclPublish && ($me['org_id'] == $delegationRequest['EventDelegation']['org_id'] || $me['org_id'] == $delegationRequest['EventDelegation']['requester_org_id'])))) {
                            echo $this->element('/genericElements/SideMenu/side_menu_divider');
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
                            echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        }
                    }
                    if (Configure::read('Plugin.ZeroMQ_enable') && $isAclZmq) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/events/pushEventToZMQ/' . h($event['Event']['id']),
                            'text' => __('Publish event to ZMQ'),
                            'message' => __('Are you sure you wish to republish the current event to the ZMQ channel?')
                        ));
                    }
                    if (Configure::read('Plugin.Kafka_enable') &&
                        Configure::read('Plugin.Kafka_event_notifications_enable') &&
                        Configure::read('Plugin.Kafka_event_notifications_topic') &&
                        $isAclKafka) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/events/pushEventToKafka/' . h($event['Event']['id']),
                            'text' => __('Publish event to Kafka'),
                            'message' => __('Are you sure you wish to republish the current event to the Kafka topic?')
                        ));
                    }
                    if (!empty($event['Orgc']['local'])) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'contact',
                            'url' => '/events/contact/' . $event['Event']['id'],
                            'text' => __('Contact Reporter')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'getPopup',
                            'params' => array($event['Event']['id'], 'events', 'exportChoice')
                        ),
                        'text' => __('Download as...')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/events/index',
                        'text' => __('List Events')
                    ));
                    if ($isAclAdd) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/events/add',
                            'text' => __('Add Event')
                        ));
                    }
                break;

                case 'tag-collections':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/tag_collections/index',
                        'text' => __('List Tag Collections')
                    ));
                    if ($isAclTagEditor) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/tag_collections/add',
                            'text' => __('Add Tag Collection')
                        ));
                        if (($menuItem === 'edit')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => '/tag_collections/edit/' . $id,
                                'text' => __('Add Tag Collection')
                            ));
                        }
                    }
                    echo sprintf(
                        '<li id="liexport"><a href="%s/tag_collections/index.json" download="tag_collections_all.json">%s</a></li>',
                        $baseurl,
                        __('Export Tag Collections')
                    );
                    echo sprintf(
                        '<li id="liimport"><a href="%s/tag_collections/import">%s</a></li>',
                        $baseurl,
                        __('Import Tag Collections')
                    );
                    break;

                case 'event-collection':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/events/index',
                        'text' => __('List Events')
                    ));
                    if ($isAclAdd) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => '/events/add',
                            'text' => __('Add Event')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array('0', 'events', 'importChoice/event-collection')
                            ),
                            'text' => __('Import from…')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'rest',
                            'url' => '/servers/rest',
                            'text' => __('REST client')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'listAttributes',
                        'url' => '/attributes/index',
                        'text' => __('List Attributes')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'searchAttributes',
                        'url' => '/attributes/search',
                        'text' => __('Search Attributes')
                    ));
                    if ($menuItem == 'searchAttributes2') {
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array(0, 'attributes', 'exportSearch')
                            ),
                            'text' => __('Download as...')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewProposals',
                        'url' => '/shadow_attributes/index/all:0',
                        'text' => __('View Proposals')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewProposalIndex',
                        'url' => '/events/proposalEventIndex',
                        'text' => __('Events with proposals')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'viewDelegations',
                        'url' => '/event_delegations/index/context:pending',
                        'text' => __('View delegation requests')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/events/export',
                        'text' => __('Export')
                    ));
                    if ($isAclAuth) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'automation',
                            'url' => '/events/automation',
                            'text' => __('Automation')
                        ));
                    }
                break;

                case 'regexp':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => sprintf(
                            '%s/regexp/index',
                            $isSiteAdmin ? '/admin' : ''
                        ),
                        'text' => __('List Regexp')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/admin/regexp/add',
                            'text' => __('New Regexp')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/admin/regexp/clean',
                            'text' => __('Perform on existing'),
                            'message' => __('Are you sure you want to rerun all of the regex rules on every attribute in the database? This task will take a long while and will modify data indiscriminately based on the rules configured.')
                        ));
                    }
                    if ($menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/admin/regexp/edit/' . h($id),
                            'text' => __('Edit Regexp')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/admin/regexp/delete/' . h($id),
                            'text' => __('Delete Regexp'),
                            'message' => __('Are you sure you want to delete # %s?', h($id))
                        ));
                    }
                break;

                case 'warninglist':
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'text' => __('View Warninglist')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/warninglists/index',
                        'text' => __('List Warninglists')
                    ));

                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/warninglists/update',
                            'text' => __('Update Warninglists'),
                            'message' => __('Are you sure you want to update all warninglists?')
                        ));
                    }
                    break;

                case 'noticelist':
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'text' => __('View Noticelist')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/noticelists/index',
                        'text' => __('List Noticelist')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                        'url' => '/noticelists/update',
                        'text' => __('Update Noticelists'),
                        'message' => __('Do you wish to continue and update all noticelists?')
                    ));
                    break;

                case 'whitelist':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => sprintf(
                            '%s/whitelists/index',
                            $isSiteAdmin ? '/admin' : ''
                        ),
                        'text' => __('List Whitelist')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/admin/whitelists/add',
                            'text' => __('New Whitelist')
                        ));
                    }
                    if ($menuItem == 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/admin/whitelists/edit' . h($id),
                            'text' => __('Edit Whitelist')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/admin/whitelists/delete/' . h($id),
                            'text' => __('Delete Whitelist'),
                            'message' => __('Are you sure you want to delete # %s?', h($id))
                        ));
                    }
                    break;

                case 'globalActions':
                    if (((Configure::read('MISP.disableUserSelfManagement') && $isAdmin) || !Configure::read('MISP.disableUserSelfManagement')) && ($menuItem === 'edit' || $menuItem === 'view' || $menuItem === 'change_pw')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/users/edit',
                            'text' => __('Edit My Profile')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/users/change_pw',
                            'text' => __('Change Password')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    } else if((Configure::read('Plugin.CustomAuth_custom_password_reset'))) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'custom_pw_reset',
                            'url' => h(Configure::read('Plugin.CustomAuth_custom_password_reset')),
                            'text' => __('Reset Password')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'view',
                        'url' => '/users/view/me',
                        'text' => __('My Profile')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'user_settings_index_me',
                        'url' => '/user_settings/index/user_id:me',
                        'text' => __('My Settings')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'user_settings_set',
                        'url' => '/user_settings/setSetting',
                        'text' => __('Set Setting')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/users/dashboard',
                        'text' => __('Dashboard')
                    ));
                    if ($isAclSharingGroup || empty(Configure::read('Security.hide_organisation_index_from_users'))) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexOrg',
                            'url' => '/organisations/index',
                            'text' => __('List Organisations')
                        ));
                    }
                    if ($menuItem === 'viewOrg') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewOrg',
                            'url' => '/organisations/view/' . h($id),
                            'text' => __('View Organisation')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'roles',
                        'url' => '/roles/index',
                        'text' => __('Role Permissions')
                    ));
                    if ($menuItem === 'editSG' || ($menuItem == 'viewSG' && $mayModify)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editSG',
                            'url' => '/sharing_groups/edit/' . h($id),
                            'text' => __('Edit Sharing Group')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewSG',
                            'url' => '/sharing_groups/view/' . h($id),
                            'text' => __('View Sharing Group')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'indexSG',
                        'url' => '/sharing_groups/index',
                        'text' => __('List Sharing Groups')
                    ));
                    if ($isAclSharingGroup) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addSG',
                            'url' => '/sharing_groups/add',
                            'text' => __('Add Sharing Group')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'userGuide',
                        'url' => '/pages/display/doc/general',
                        'text' => __('User Guide')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/users/terms',
                        'text' => __('Terms & Conditions')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/users/statistics',
                        'text' => __('Statistics')
                    ));
                    break;

                case 'sync':
                    if ($me['Role']['perm_sync']) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/servers/createSync',
                            'text' => __('Create Sync Config')
                        ));
                    }
                    if ($menuItem === 'import' && ($me['Role']['perm_site_admin'])) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/servers/import',
                            'text' => __('Import Server Settings')
                        ));
                    }
                    if ($menuItem === 'previewEvent' && ($isSiteAdmin || $hostOrg)) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => sprintf(
                                '/servers/previewIndex/%s',
                                h($server['Server']['id'])
                            ),
                            'text' => __('Explore Remote Server')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => sprintf(
                                '/servers/previewEvent/%s/%s',
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
                                '/servers/pull/%s/%s',
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
                                '/servers/previewIndex/%s',
                                h($id)
                            ),
                            'text' => __('Explore Remote Server')
                        ));
                    }
                    if ($menuItem === 'edit' && $isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => '/servers/edit/' . h($id),
                            'text' => __('Edit Server')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'pull',
                            'url' => sprintf(
                                '/servers/delete/%s',
                                $this->Form->value('Server.id')
                            ),
                            'text' => __('Delete'),
                            'message' => __('Are you sure you want to delete # %s?', $this->Form->value('Server.id'))
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/servers/index',
                        'text' => __('List Servers')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/servers/add',
                            'text' => __('New Servers')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/communities/index',
                            'text' => __('List Communities'),
                            'element_id' => 'list_communities'
                        ));
                        if ($menuItem === 'view_community' || $menuItem === 'request_community_access') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'text' => __('Request Access'),
                                'url' => '/communities/requestAccess/' . h($community['uuid']),
                                'element_id' => 'request_community_access'
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'text' => __('View community'),
                                'url' => '/communities/view/' . h($community['uuid']),
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
                    break;

                case 'admin':
                    if ($menuItem === 'editUser' || $menuItem === 'viewUser') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewUser',
                            'url' => '/admin/users/view/' . h($id),
                            'text' => __('View User')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'initiatePasswordReset',
                                'params' => array($id)
                            ),
                            'text' => __('Reset Password')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editUser',
                            'url' => '/admin/users/edit/' . h($id),
                            'text' => __('Edit User')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'deleteUser',
                            'url' => '/admin/users/delete/' . h($id),
                            'text' => __('Delete User'),
                            'message' => __('Are you sure you want to delete # %s? It is highly recommended to never delete users but to disable them instead.', h($id))
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    }
                    if ($isSiteAdmin && $menuItem === 'editRole') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'editRole',
                            'url' => '/admin/roles/edit/' . h($id),
                            'text' => __('Edit Role')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'deleteRole',
                            'url' => '/admin/roles/delete/' . h($id),
                            'text' => __('Delete Role'),
                            'message' => __('Are you sure you want to delete # %s?', h($id))
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    }
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addUser',
                            'url' => '/admin/users/add',
                            'text' => __('Add User')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexUser',
                            'url' => '/admin/users/index',
                            'text' => __('List Users')
                        ));
                    }
                    if ($isAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'user_settings_index',
                            'url' => '/user_settings/index/user_id:all',
                            'text' => __('User settings')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'user_settings_set',
                            'url' => '/user_settings/setSetting',
                            'text' => __('Set Setting')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'contact',
                            'url' => '/admin/users/email',
                            'text' => __('Contact Users')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addOrg',
                            'url' => '/admin/organisations/add',
                            'text' => __('Add Organisation')
                        ));
                        if ($menuItem === 'editOrg' || $menuItem === 'viewOrg') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'editOrg',
                                'url' => '/admin/organisations/edit/' . h($id),
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
                        }
                        if ($menuItem === 'editOrg' || $menuItem === 'viewOrg') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'viewOrg',
                                'url' => '/organisations/view/' . h($id),
                                'text' => __('View Organisation')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'indexOrg',
                            'url' => '/organisations/index',
                            'text' => __('List Organisations')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'addRole',
                            'url' => '/admin/roles/add',
                            'text' => __('Add Role')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'indexRole',
                        'url' => '/admin/roles/index',
                        'text' => __('List Roles')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/servers/serverSettings',
                            'text' => __('Server Settings & Maintenance')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/servers/updateProgress',
                            'text' => __('Update Progress')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        if (Configure::read('MISP.background_jobs')) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'jobs',
                                'url' => '/jobs/index',
                                'text' => __('Jobs')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_divider');
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'tasks',
                                'url' => '/tasks',
                                'text' => __('Scheduled Tasks')
                            ));
                        }
                        if (Configure::read('MISP.enableEventBlacklisting') !== false) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'eventBlacklistsAdd',
                                'url' => '/eventBlacklists/add',
                                'text' => __('Blacklists Event')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'eventBlacklists',
                                'url' => '/eventBlacklists',
                                'text' => __('Manage Event Blacklists')
                            ));
                        }
                        if (!Configure::check('MISP.enableOrgBlacklisting') || Configure::read('MISP.enableOrgBlacklisting') !== false) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'orgBlacklistsAdd',
                                'url' => '/orgBlacklists/add',
                                'text' => __('Blacklists Organisation')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'orgBlacklists',
                                'url' => '/orgBlacklists',
                                'text' => __('Manage Org Blacklists')
                            ));
                        }
                    }
                    break;

                case 'logs':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/admin/logs/index',
                        'text' => __('List Logs')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/admin/logs/search',
                        'text' => __('Search Logs')
                    ));
                    break;

                case 'threads':
                    if ($menuItem === 'add' || $menuItem === 'view') {
                        if (!(empty($thread_id) && empty($target_type))) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'url' => '/threads/view/' . h($thread_id),
                                'text' => __('View Thread')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'add_post',
                                'url' => '/posts/add/thread/' . h($thread_id),
                                'text' => __('Add Post')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        }
                    }
                    if ($menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => '/threads/view/' . h($thread_id),
                            'text' => __('View Thread')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => '/threads/view/' . h($id),
                            'text' => __('Edit Post')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/threads/index',
                        'text' => __('List Threads')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/posts/add',
                        'text' => __('New Thread')
                    ));
                    break;

                case 'tags':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'indexfav',
                        'url' => '/tags/index/1',
                        'text' => __('List Favourite Tags')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/tags/index',
                        'text' => __('List Tags')
                    ));
                    if ($isAclTagEditor) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/tags/add',
                            'text' => __('Add Tag')
                        ));
                    }
                    if ($menuItem === 'edit') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'edit',
                            'url' => '#',
                            'text' => __('Edit Tag')
                        ));
                    }
                    if ($menuItem === 'viewGraph') {
                        if (!empty($taxonomy)) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'taxonomyview',
                                'url' => '/taxonomies/view/' . h($taxonomy['Taxonomy']['id']),
                                'text' => __('View Taxonomy')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewGraph',
                            'url' => '/tags/viewGraph/' . h($id),
                            'text' => __('View Correlation Graph')
                        ));
                    }
                break;

                case 'taxonomies':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/taxonomies/index',
                        'text' => __('List Taxonomies')
                    ));
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'text' => __('View Taxonomy')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'delete',
                            'onClick' => array(
                                'function' => 'deleteObject',
                                'params' => array('taxonomies', 'delete', h($id), h($id))
                            ),
                            'text' => __('Delete Taxonomy')
                        ));
                    }
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'event_id' => 'update',
                            'url' => '/taxonomies/update',
                            'text' => __('Update Taxonomies')
                        ));
                    }
                    break;

                case 'templates':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/templates/index',
                        'text' => __('List Templates')
                    ));
                    if ($isSiteAdmin || $isAclTemplate) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/templates/add',
                            'text' => __('Add Template')
                        ));
                    }
                    if (($menuItem === 'view' || $menuItem === 'edit')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => '/templates/view/' . h($id),
                            'text' => __('View Template')
                        ));
                        if ($mayModify) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => '/templates/edit/' . h($id),
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
                                'url' => '/decayingModel/update',
                                'text' => __('Update Default Models')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                                'event_id' => 'update',
                                'url' => '/decayingModel/update/true',
                                'text' => __('Force Update Default Models')
                            ));
                        }
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/decayingModel/import',
                            'text' => __('Import Decaying Model')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/decayingModel/add',
                            'text' => __('Add Decaying Model')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/decayingModel/decayingTool',
                            'text' => __('Decaying Tool')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_divider');
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/decayingModel/index',
                        'text' => __('List Decaying Models')
                    ));
                    if (($menuItem === 'view' || $menuItem === 'edit')) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => '/decayingModel/view/' . h($id),
                            'text' => __('View Decaying Model')
                        ));
                        if ($isSiteAdmin) {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => '/decayingModel/edit/' . h($id),
                                'text' => __('Edit Decaying Model')
                            ));
                        }
                    }
                    break;

                case 'feeds':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/feeds/index',
                        'text' => __('List Feeds')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/feeds/searchCaches',
                        'text' => __('Search Feed Caches')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/feeds/add',
                            'text' => __('Add Feed')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'import',
                            'url' => '/feeds/importFeeds',
                            'text' => __('Import Feeds from JSON')
                        ));
                    }
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'compare',
                        'url' => '/feeds/compareFeeds',
                        'text' => __('Feed overlap analysis matrix')
                    ));
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'element_id' => 'export',
                        'url' => '/feeds/index.json',
                        'text' => __('Export Feed settings'),
                        'download' => 'feed_index.json'
                    ));
                    if ($isSiteAdmin) {
                        if ($menuItem === 'edit' || $menuItem === 'view') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => '/feeds/edit/' . h($feed['Feed']['id']),
                                'text' => __('Edit Feed')
                            ));
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'view',
                                'url' => '/feeds/view/' . h($feed['Feed']['id']),
                                'text' => __('View Feed')
                            ));
                        } else if ($menuItem === 'previewIndex') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'previewIndex',
                                'url' => '/feeds/previewIndex/' . h($feed['Feed']['id']),
                                'text' => __('PreviewIndex')
                            ));
                        } else if ($menuItem === 'previewEvent') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'previewEvent',
                                'url' => '/feeds/previewEvent/' . h($feed['Feed']['id']) . '/' . h($id),
                                'text' => __('PreviewEvent')
                            ));
                        }
                    }
                break;

                case 'news':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/news/index',
                        'text' => __('View News')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'url' => '/news/add',
                            'text' => __('Add News Item')
                        ));
                        if ($menuItem === 'edit') {
                            echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                                'element_id' => 'edit',
                                'url' => '#',
                                'text' => __('Edit News Item')
                            ));
                        }
                    }
                    break;

                case 'galaxies':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/galaxies/index',
                        'text' => __('List Galaxies')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'element_id' => 'update',
                            'url' => '/galaxies/update',
                            'text' => __('Update Galaxies'),
                            'message' => __('Are you sure you want to reimport all galaxies from the submodule?')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'element_id' => 'forceupdate',
                            'url' => '/galaxies/update/force:1',
                            'text' => __('Force Update Galaxies'),
                            'message' => __('Are you sure you want to drop and reimport all galaxies from the submodule?')
                        ));
                    }
                    if ($menuItem === 'viewGraph' || $menuItem === 'view_cluster') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'url' => '/galaxies/view/' . h($galaxy_id),
                            'text' => __('View Galaxy')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view_cluster',
                            'url' => '/galaxy_clusters/view/' . h($id),
                            'text' => __('View Cluster')
                        ));
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'viewGraph',
                            'url' => '/galaxies/viewGraph/' . h($id),
                            'text' => __('View Correlation Graph')
                        ));
                    }
                    if ($menuItem === 'view') {
                        echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                            'element_id' => 'view',
                            'text' => __('View Galaxy')
                        ));
                    }
                    break;

                case 'objectTemplates':
                    echo $this->element('/genericElements/SideMenu/side_menu_link', array(
                        'url' => '/objectTemplates/index',
                        'text' => __('List Object Templates')
                    ));
                    if ($isSiteAdmin) {
                        echo $this->element('/genericElements/SideMenu/side_menu_post_link', array(
                            'url' => '/objectTemplates/update',
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
            }
        ?>
    </ul>
</div>
<script type="text/javascript">
$(document).ready(function() {
    $('#li<?php echo h($menuItem); ?>').addClass("active");
});
</script>
