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
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'template_populate_results',
                            'url' => '/templates/index',
                            'text' => __('Populate From Template')
                        ));
                    }
                    if ($menuItem === 'freetextResults') {
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'freetextResults',
                            'url' => '#',
                            'text' => __('Freetext Import Result')
                        ));
                        echo $this->element('/side_menu_divider');
                    }
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'viewEvent',
                        'url' => '/events/view/' .  $event['Event']['id'],
                        'text' => __('View Event')
                    ));
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'viewGraph',
                        'url' => '/events/viewGraph/' .  $event['Event']['id'],
                        'text' => __('View Correlation Graph')
                    ));
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'eventLog',
                        'url' => '/logs/event_index/' .  $event['Event']['id'],
                        'text' => __('View Event History')
                    ));
                    echo $this->element('/side_menu_divider');
                    if ($isSiteAdmin || (isset($mayModify) && $mayModify)) {
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'editEvent',
                            'url' => '/events/edit/' .  $event['Event']['id'],
                            'text' => __('Edit Event')
                        ));
                        echo '<li>' . $this->Form->postLink(__('Delete Event'), array('controller' => 'events', 'action' => 'delete', h($event['Event']['id'])), null, __('Are you sure you want to delete # %s?', h($event['Event']['id']))) . '</li>';
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'addAttribute',
                            'url' => '/attributes/add/' .  $event['Event']['id'],
                            'text' => __('Add Attribute')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array($event['Event']['id'], 'objectTemplates', 'objectChoice')
                            ),
                            'text' => __('Add Object')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'addAttachment',
                            'url' => '/attributes/add_attachment/' .  $event['Event']['id'],
                            'text' => __('Add Attachment')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array($event['Event']['id'], 'events', 'importChoice')
                            ),
                            'text' => __('Populate from...')
                        ));
                        if ($menuItem === 'populateFromtemplate') {
                            echo $this->element('/side_menu_link', array(
                                'url' => '/templates/populateEventFromTemplate/' . $template_id . '/' .  $event['Event']['id'],
                                'text' => __('Populate From Template')
                            ));
                        }
                        echo $this->element('/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'genericPopup',
                                'params' => array($baseurl . '/events/enrichEvent/' . $event['Event']['id'], '#confirmation_box')
                            ),
                            'text' => __('Enrich Event')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'merge',
                            'url' => '/events/merge/' . $event['Event']['id'],
                            'text' => __('Merge attributes from...')
                        ));
                    }
                    if (($isSiteAdmin && (!isset($mayModify) || !$mayModify)) || (!isset($mayModify) || !$mayModify)) {
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'proposeAttribute',
                            'url' => '/shadow_attributes/add/' . $event['Event']['id'],
                            'text' => __('Propose Attribute')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'proposeAttachment',
                            'url' => '/shadow_attributes/add_attachment/' . $event['Event']['id'],
                            'text' => __('Propose Attachment')
                        ));
                    }
                    echo $this->element('/side_menu_divider');
                    $publishButtons = ' hidden';
                    if (isset($event['Event']['published']) && 0 == $event['Event']['published'] && ($isSiteAdmin || (isset($mayPublish) && $mayPublish))) $publishButtons = "";
                    echo $this->element('/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'publishPopup',
                            'params' => array($event['Event']['id'], 'alert')
                        ),
                        'class' => 'publishButtons not-published ' . $publishButtons,
                        'text' => __('Publish Event')
                    ));
                    echo $this->element('/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'publishPopup',
                            'params' => array($event['Event']['id'], 'publish')
                        ),
                        'class' => 'publishButtons not-published ' . $publishButtons,
                        'text' => __('Publish (no email)')
                    ));
                    if (Configure::read('MISP.delegation')) {
                        if ((Configure::read('MISP.unpublishedprivate') || (isset($event['Event']['distribution']) && $event['Event']['distribution'] == 0)) && (!isset($delegationRequest) || !$delegationRequest) && ($isSiteAdmin || (isset($isAclDelegate) && $isAclDelegate))) {
                            echo $this->element('/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'delegatePopup',
                                    'params' => array($event['Event']['id'])
                                ),
                                'text' => __('Delegate Publishing')
                            ));
                        }
                        if (isset($delegationRequest) && $delegationRequest && ($isSiteAdmin || ($isAclPublish && ($me['org_id'] == $delegationRequest['EventDelegation']['org_id'] || $me['org_id'] == $delegationRequest['EventDelegation']['requester_org_id'])))) {
                            echo $this->element('/side_menu_divider');
                            if ($isSiteAdmin || ($isAclPublish && ($me['org_id'] == $delegationRequest['EventDelegation']['org_id']))) {
                                echo $this->element('/side_menu_link', array(
                                    'onClick' => array(
                                        'function' => 'genericPopup',
                                        'params' => array($baseurl . '/event_delegations/acceptDelegation/' . $delegationRequest['EventDelegation']['id'], '#confirmation_box')
                                    ),
                                    'text' => __('Accept Delegation Request')
                                ));
                            }
                            echo $this->element('/side_menu_link', array(
                                'onClick' => array(
                                    'function' => 'genericPopup',
                                    'params' => array($baseurl . '/event_delegations/deleteDelegation/' . $delegationRequest['EventDelegation']['id'], '#confirmation_box')
                                ),
                                'text' => __('Discard Delegation Request')
                            ));
                            echo $this->element('/side_menu_divider');
                        }
                    }
                    if (Configure::read('Plugin.ZeroMQ_enable') && $isAclZmq) {
                        echo '<li>' . $this->Form->postLink(__('Publish event to ZMQ'), array('action' => 'pushEventToZMQ', $event['Event']['id'])) . '</li>';
                    }
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'contact',
                        'url' => '/events/contact/' . $event['Event']['id'],
                        'text' => __('Contact Reporter')
                    ));
                    echo $this->element('/side_menu_link', array(
                        'onClick' => array(
                            'function' => 'getPopup',
                            'params' => array($event['Event']['id'], 'events', 'exportChoice')
                        ),
                        'text' => __('Download as...')
                    ));
                    echo $this->element('/side_menu_divider');
                    echo $this->element('/side_menu_link', array(
                        'url' => '/events/index',
                        'text' => __('List Events')
                    ));
                    if ($isAclAdd) {
                        echo $this->element('/side_menu_link', array(
                            'url' => '/events/add',
                            'text' => __('Add Event')
                        ));
                    }
                break;

                case 'event-collection':
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/events/index',
                        'text' => __('List Events')
                    ));
                    if ($isAclAdd) {
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'add',
                            'url' => '/events/add',
                            'text' => __('Add Event')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'onClick' => array(
                                'function' => 'getPopup',
                                'params' => array('0', 'events', 'importChoice/event-collection')
                            ),
                            'text' => __('Import from…')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'rest',
                            'url' => '/servers/rest',
                            'text' => __('REST client')
                        ));
                    }
                    echo $this->element('/side_menu_divider');
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'index',
                        'url' => '/attributes/index',
                        'text' => __('List Attributes')
                    ));
                    echo $this->element('/side_menu_link', array(
                        'element_id' => 'search',
                        'url' => '/attributes/search',
                        'text' => __('Search Attributes')
                    ));
                    if ($menuItem == 'searchAttributes2') {
                        echo $this->element('/side_menu_divider');
                        echo $this->element('/side_menu_link', array(
                            'url' => '/events/downloadSearchResult.json',
                            'text' => __('Download results as JSON')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'url' => '/events/downloadSearchResult.xml',
                            'text' => __('Download results as XML')
                        ));
                        echo $this->element('/side_menu_link', array(
                            'url' => '/events/csv/download/search',
                            'text' => __('Download results as CSV')
                        ));
                    }
                    echo $this->element('/side_menu_divider');
                    echo $this->element('/side_menu_link', array(
                        'url' => '/shadow_attributes/index',
                        'text' => __('View Proposals')
                    ));
                    echo $this->element('/side_menu_link', array(
                        'url' => '/events/proposalEventIndex',
                        'text' => __('Events with proposals')
                    ));
                    echo $this->element('/side_menu_divider');
                    echo $this->element('/side_menu_link', array(
                        'url' => '/events/export',
                        'text' => __('Export')
                    ));
                    if ($isAclAuth) {
                        echo $this->element('/side_menu_link', array(
                            'element_id' => 'automation',
                            'url' => '/events/automation',
                            'text' => __('Automation')
                        ));
                    }
                break;

                case 'regexp': ?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Regexp'), array('admin' => $isSiteAdmin, 'action' => 'index'));?></li>
                    <?php if ($isSiteAdmin): ?>
                    <li id='liadd'><?php echo $this->Html->link(__('New Regexp'), array('admin' => true, 'action' => 'add'));?></li>
                    <li><?php echo $this->Form->postLink(__('Perform on existing'), array('admin' => true, 'action' => 'clean'));?></li>
                    <?php endif;
                    if ($menuItem == 'edit'):?>
                    <li class="divider"></li>
                    <li class="active"><?php echo $this->Html->link(__('Edit Regexp'), array('admin' => true, 'action' => 'edit', h($id)));?></li>
                    <li><?php echo $this->Form->postLink(__('Delete Regexp'), array('admin' => true, 'action' => 'delete', h($id)), null, __('Are you sure you want to delete # %s?', h($id)));?></li>
                    <?php
                    endif;
                break;

                case 'warninglist':?>
                    <?php if ($menuItem == 'view'): ?><li class="active"><a href="#"><?php echo __('View Warninglist');?></a></li><?php endif;?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Warninglists'), array('action' => 'index'));?></li>
                    <?php if ($isSiteAdmin): ?>
                    <li><?php echo $this->Form->postLink(__('Update Warninglists'), '/warninglists/update'); ?></li>
                    <?php
                        endif;
                break;

                case 'noticelist':?>
                    <?php if ($menuItem == 'view'): ?><li class="active"><a href="#"><?php echo __('View Noticelist');?></a></li><?php endif;?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Noticelists'), array('action' => 'index'));?></li>
                    <?php if ($isSiteAdmin): ?>
                    <li><?php echo $this->Form->postLink(__('Update Noticelists'), '/noticelists/update'); ?></li>
                    <?php
                        endif;
                break;

                case 'whitelist':?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Whitelist'), array('admin' => $isSiteAdmin, 'action' => 'index'));?></li>
                    <?php if ($isSiteAdmin): ?>
                    <li id='liadd'><?php echo $this->Html->link(__('New Whitelist'), array('admin' => true, 'action' => 'add'));?></li>
                    <?php endif;
                    if ($menuItem == 'edit'):?>
                    <li class="divider"></li>
                    <li class="active"><?php echo $this->Html->link(__('Edit Whitelist'), array('admin' => true, 'action' => 'edit', h($id)));?></li>
                    <li><?php echo $this->Form->postLink(__('Delete Whitelist'), array('admin' => true, 'action' => 'delete', h($id)), null, __('Are you sure you want to delete # %s?', h($id)));?></li>
                    <?php
                    endif;
                break;

                case 'globalActions':
                    if (((Configure::read('MISP.disableUserSelfManagement') && $isAdmin) || !Configure::read('MISP.disableUserSelfManagement')) && ($menuItem === 'edit' || $menuItem === 'view')): ?>
                    <li id='liedit'><?php echo $this->Html->link(__('Edit My Profile', true), array('action' => 'edit')); ?></li>
                    <li id='liedit'><?php echo $this->Html->link(__('Change Password', true), array('action' => 'change_pw')); ?></li>
                    <li class="divider"></li>
                    <?php elseif (Configure::read('Plugin.CustomAuth_custom_password_reset')): ?>
                    <li id='lipwreset'><a href="<?php echo h(Configure::read('Plugin.CustomAuth_custom_password_reset'));?>">Reset Password</a></li>
                    <?php endif; ?>
                    <li id='liview'><a href="<?php echo $baseurl;?>/users/view/me"><?php echo __('My Profile');?></a></li>
                    <li id='lidashboard'><a href="<?php echo $baseurl;?>/users/dashboard"><?php echo __('Dashboard');?></a></li>
                    <?php
                        if ($isAclSharingGroup || empty(Configure::read('Security.hide_organisation_index_from_users'))):
                    ?>
                            <li id='liindexOrg'><a href="<?php echo $baseurl;?>/organisations/index"><?php echo __('List Organisations');?></a></li>
                    <?php
                        endif;
                        if ($menuItem === 'viewOrg'):
                    ?>
                        <li class="active"><a href="<?php echo $baseurl;?>/organisations/view/<?php echo h($id);?>"><?php echo __('View Organisation');?></a></li>
                    <?php
                        endif;
                    ?>
                    <li id='liroles'><a href="<?php echo $baseurl;?>/roles/index"><?php echo __('Role Permissions');?></a></li>
                    <li class="divider"></li>
                    <?php if ($menuItem === 'editSG' || ($menuItem == 'viewSG' && $mayModify)): ?>
                        <li id='lieditSG'><a href="<?php echo $baseurl;?>/sharing_groups/edit/<?php echo h($id); ?>"><?php echo __('Edit Sharing Group');?></a></li>
                        <li id='liviewSG'><a href="<?php echo $baseurl;?>/sharing_groups/view/<?php echo h($id);?>"><?php echo __('View Sharing Group');?></a></li>
                    <?php endif; ?>
                    <li id='liindexSG'><a href="<?php echo $baseurl;?>/sharing_groups/index"><?php echo __('List Sharing Groups');?></a></li>
                    <li id='liaddSG'><a href="<?php echo $baseurl;?>/sharing_groups/add"><?php echo __('Add Sharing Group');?></a></li>
                    <li class="divider"></li>
                    <li id='liuserGuide'><a href="<?php echo $baseurl;?>/pages/display/doc/general"><?php echo __('User Guide');?></a></li>
                    <li id='literms'><a href="<?php echo $baseurl;?>/users/terms"><?php echo __('Terms &amp; Conditions');?></a></li>
                    <li id='listatistics'><a href="<?php echo $baseurl;?>/users/statistics"><?php echo __('Statistics');?></a></li>
                    <?php
                break;

                case 'sync':
                    if ($menuItem === 'previewEvent' && $isSiteAdmin) : ?>
                    <li class="active"><?php echo $this->Html->link(__('Explore Remote Event'), array('controller' => 'servers', 'action' => 'previewEvent', h($server['Server']['id']), h($event['Event']['id']))); ?></li>
                    <li><?php echo $this->Form->postLink(__('Fetch This Event'), '/servers/pull/' . $server['Server']['id'] . '/' . $event['Event']['id'], null, __('Are you sure you want to fetch and save this event on your instance?', $this->Form->value('Server.id'))); ?></li>
                    <li><?php echo $this->Html->link(__('Explore Remote Server'), array('controller' => 'servers', 'action' => 'previewIndex', h($server['Server']['id']))); ?></li>
                    <?php endif;
                    if ($menuItem === 'previewIndex' && $isSiteAdmin) : ?>
                    <li class="active"><?php echo $this->Html->link(__('Explore Remote Server'), array('controller' => 'servers', 'action' => 'previewIndex', h($id))); ?></li>
                    <?php endif; ?>
                    <?php if ($menuItem === 'edit' && $isSiteAdmin): ?>
                    <li class="active"><?php echo $this->Html->link(__('Edit Server'), array('controller' => 'servers', 'action' => 'edit')); ?></li>
                    <li><?php echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $this->Form->value('Server.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Server.id'))); ?></li>
                    <li class="divider"></li>
                    <?php endif; ?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index'));?></li>
                    <?php if ($isSiteAdmin): ?>
                    <li id='liadd'><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>
                    <?php endif;?>
                    <?php
                break;

                case 'admin':
                    if ($menuItem === 'editUser' || $menuItem === 'viewUser'): ?>
                    <li id='liviewUser'><?php echo $this->Html->link(__('View User'), array('controller' => 'users', 'action' => 'view', 'admin' => true, h($id))); ?> </li>
                    <li><a href="#/" onClick="initiatePasswordReset('<?php echo h($id); ?>');"><?php echo __('Reset Password');?></a></li>
                    <li id='lieditUser'><?php echo $this->Html->link(__('Edit User'), array('controller' => 'users', 'action' => 'edit', 'admin' => true, h($id))); ?> </li>
                    <li><?php echo $this->Form->postLink(__('Delete User'), array('admin' => true, 'action' => 'delete', h($id)), null, __('Are you sure you want to delete # %s? It is highly recommended to never delete users but to disable them instead.', h($id)));?></li>
                    <li class="divider"></li>
                    <?php endif;
                    if ($isSiteAdmin && $menuItem === 'editRole'): ?>
                    <li class="active"><?php echo $this->Html->link(__('Edit Role'), array('controller' => 'roles', 'action' => 'edit', 'admin' => true, h($id))); ?> </li>
                    <li><?php echo $this->Form->postLink(__('Delete Role'), array('controller' => 'roles', 'admin' => true, 'action' => 'delete', h($id)), null, __('Are you sure you want to delete # %s?', h($id)));?></li>
                    <li class="divider"></li>
                    <?php endif;
                    if ($isSiteAdmin): ?>
                    <li id='liaddUser'><?php echo $this->Html->link(__('Add User'), array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
                    <li id='liindexUser'><?php echo $this->Html->link(__('List Users'), array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
                    <?php endif; ?>
                    <?php if ($isAdmin): ?>
                    <li id='licontact'><?php echo $this->Html->link(__('Contact Users'), array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
                    <?php endif; ?>
                    <li class="divider"></li>
                    <?php if ($isSiteAdmin): ?>
                    <li id='liaddOrg'><a href="<?php echo $baseurl;?>/admin/organisations/add"><?php echo __('Add Organisation');?></a></li>
                    <?php if ($menuItem === 'editOrg' || $menuItem === 'viewOrg'): ?>
                        <li id='lieditOrg'><a href="<?php echo $baseurl;?>/admin/organisations/edit/<?php echo h($id);?>"><?php echo __('Edit Organisation');?></a></li>
                        <li id='limergeOrg'><a class="useCursorPointer" onClick="getPopup('<?php echo h($id); ?>', 'organisations', 'merge', 'admin');"><?php echo __('Merge Organisation');?></a></li>
                    <?php endif;?>
                    <?php if ($menuItem === 'editOrg' || $menuItem === 'viewOrg'): ?>
                        <li id='liviewOrg'><a href="<?php echo $baseurl;?>/organisations/view/<?php echo h($id);?>"><?php echo __('View Organisation');?></a></li>
                    <?php endif;?>
                    <li id='liindexOrg'><a href="<?php echo $baseurl;?>/organisations/index"><?php echo __('List Organisations');?></a></li>
                    <li class="divider"></li>
                    <li id='liaddRole'><?php echo $this->Html->link(__('Add Role'), array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
                    <?php endif; ?>
                    <li id='liindexRole'><?php echo $this->Html->link(__('List Roles'), array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
                    <?php if ($isSiteAdmin): ?>
                        <li class="divider"></li>
                        <li id='liserverSettings'><a href="<?php echo $baseurl;?>/servers/serverSettings"><?php echo __('Server Settings & Maintenance');?></a></li>
                        <li class="divider"></li>
                        <?php if (Configure::read('MISP.background_jobs')): ?>
                            <li id='lijobs'><a href="<?php echo $baseurl;?>/jobs/index"><?php echo __('Jobs');?></a></li>
                            <li class="divider"></li>
                            <li id='litasks'><a href="<?php echo $baseurl;?>/tasks"><?php echo __('Scheduled Tasks');?></a></li>
                        <?php endif;
                        if (Configure::read('MISP.enableEventBlacklisting') !== false): ?>
                            <li <?php if ($menuItem === 'eventBlacklistsAdd') echo 'class="active"';?>><a href="<?php echo $baseurl;?>/eventBlacklists/add"><?php echo __('Blacklists Event');?></a></li>
                            <li <?php if ($menuItem === 'eventBlacklists') echo 'class="active"';?>><a href="<?php echo $baseurl;?>/eventBlacklists"><?php echo __('Manage Event Blacklists');?></a></li>
                        <?php endif;
                        if (!Configure::check('MISP.enableOrgBlacklisting') || Configure::read('MISP.enableOrgBlacklisting') !== false): ?>
                            <li <?php if ($menuItem === 'orgBlacklistsAdd') echo 'class="active"';?>><a href="<?php echo $baseurl;?>/orgBlacklists/add"><?php echo __('Blacklists Organisation');?></a></li>
                            <li <?php if ($menuItem === 'orgBlacklists') echo 'class="active"';?>><a href="<?php echo $baseurl;?>/orgBlacklists"><?php echo __('Manage Org Blacklists');?></a></li>
                        <?php endif;
                    endif;
                break;

                case 'logs': ?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Logs'), array('admin' => true, 'action' => 'index'));?></li>
                    <li id='lisearch'><?php echo $this->Html->link(__('Search Logs'), array('admin' => true, 'action' => 'search'));?></li>
                    <?php
                break;

                case 'threads':

                    if ($menuItem === 'add' || $menuItem === 'view') {
                        if (!(empty($thread_id) && empty($target_type))) { ?>
                    <li  id='view'><?php echo $this->Html->link(__('View Thread'), array('controller' => 'threads', 'action' => 'view', h($thread_id)));?></li>
                    <li  id='add'><?php echo $this->Html->link(__('Add Post'), array('controller' => 'posts', 'action' => 'add', 'thread', h($thread_id)));?></li>
                    <li class="divider"></li>
                    <?php
                        }
                    }
                    if ($menuItem === 'edit') { ?>
                        <li><?php echo $this->Html->link(__('View Thread'), array('controller' => 'threads', 'action' => 'view', h($thread_id)));?></li>
                        <li class="active"><?php echo $this->Html->link(__('Edit Post'), array('controller' => 'threads', 'action' => 'view', h($id)));?></li>
                        <li class="divider"></li>
                    <?php
                    }
                    ?>
                    <li id='liindex'><?php echo $this->Html->link(__('List Threads'), array('controller' => 'threads', 'action' => 'index'));?></li>
                    <li id='liadd'><a href = "<?php echo Configure::read('MISP.baseurl');?>/posts/add"><?php echo __('New Thread');?></a></li>
                    <?php
                break;

                case 'tags': ?>
                    <li id='liindexfav'><?php echo $this->Html->link(__('List Favourite Tags'), array('action' => 'index', true));?></li>
                    <li id='liindex'><?php echo $this->Html->link(__('List Tags'), array('action' => 'index'));?></li>
                <?php
                    if ($isAclTagEditor):
                ?>
                        <li id='liadd'><?php echo $this->Html->link(__('Add Tag'), array('action' => 'add'));?></li>
                <?php
                    endif;
                    if ($menuItem === 'edit'):
                ?>
                        <li class="active"><?php echo $this->Html->link(__('Edit Tag'), array('action' => 'edit'));?></li>
                <?php
                    endif;
                    if ($menuItem === 'viewGraph'):
                        if (!empty($taxonomy)):
                ?>
                            <li><a href="<?php echo $baseurl; ?>/taxonomies/view/<?php echo h($taxonomy['Taxonomy']['id']); ?>"><?php echo __('View Taxonomy');?></a></li>
                <?php
                        endif;
                ?>
                    <li id='liviewGraph'><a href="<?php echo $baseurl;?>/tags/viewGraph/<?php echo h($id); ?>"><?php echo __('View Correlation Graph');?></a></li>
                <?php
                    endif;
                break;

                case 'taxonomies': ?>
                    <li id='liindex'><a href="<?php echo $baseurl;?>/taxonomies/index"><?php echo __('List Taxonomies');?></a></li>
                    <?php if ($menuItem === 'view'): ?>
                        <li id='liview'><a href=""><?php echo __('View Taxonomy');?></a></li>
                        <li id='lidelete'><a class="useCursorPointer" onClick="deleteObject('taxonomies', 'delete', '<?php echo h($id); ?>', '<?php echo h($id); ?>');"><?php echo __('Delete Taxonomy');?></a></li>
                    <?php
                    endif;
                    if ($isSiteAdmin):
                    ?>
                        <li id='liupdate'><?php echo $this->Form->postLink('Update Taxonomies', array('controller' => 'taxonomies', 'action' => 'update'));?></li>
                    <?php
                    endif;
                break;

                case 'templates': ?>
                    <li id='liindex'><a href="<?php echo $baseurl;?>/templates/index"><?php echo __('List Templates');?></a></li>
                    <?php if ($isSiteAdmin || $isAclTemplate): ?>
                    <li id='liadd'><a href="<?php echo $baseurl;?>/templates/add"><?php echo __('Add Template');?></a></li>
                    <?php
                    endif;
                    if (($menuItem === 'view' || $menuItem === 'edit')):
                    ?>
                    <li id='liview'><a href="<?php echo $baseurl;?>/templates/view/<?php echo h($id); ?>"><?php echo __('View Template');?></a></li>
                    <?php if ($mayModify): ?>
                    <li id='liedit'><a href="<?php echo $baseurl;?>/templates/edit/<?php echo h($id); ?>"><?php echo __('Edit Template');?></a></li>
                    <?php
                    endif;
                    endif;
                break;

                case 'feeds': ?>
                    <li id='liindex'><a href="<?php echo $baseurl;?>/feeds/index"><?php echo __('List Feeds');?></a></li>
                    <li id='liadd'><a href="<?php echo $baseurl;?>/feeds/add"><?php echo __('Add Feed');?></a></li>
                    <li id='liadd'><a href="<?php echo $baseurl;?>/feeds/importFeeds"><?php echo __('Import Feeds from JSON');?></a></li>
                    <li id='licompare'><a href="<?php echo $baseurl;?>/feeds/compareFeeds"><?php echo __('Feed overlap analysis matrix');?></a></li>
                    <li id='liexport'><a href="<?php echo $baseurl;?>/feeds/index.json" download="feed_index.json"><?php echo __('Export Feed settings');?></a></li>
                    <?php if ($menuItem === 'edit'): ?>
                        <li class="active"><a href="#"><?php echo __('Edit Feed');?></a></li>
                    <?php elseif ($menuItem === 'previewIndex'): ?>
                        <li id='lipreviewIndex'><a href="<?php echo $baseurl;?>/feeds/previewIndex/<?php echo h($feed['Feed']['id']); ?>"><?php echo __('PreviewIndex');?></a></li>
                    <?php elseif ($menuItem === 'previewEvent'): ?>
                        <li id='lipreviewEvent'><a href="<?php echo $baseurl;?>/feeds/previewEvent/<?php echo h($feed['Feed']['id']); ?>/<?php echo h($id);?>"><?php echo __('PreviewEvent');?></a></li>
                    <?php endif;
                break;

                case 'news': ?>
                    <li id='liindex'><a href="<?php echo $baseurl;?>/news/index"><?php echo __('View News');?></a></li>
                <?php
                    if ($isSiteAdmin):
                ?>
                        <li id='liadd'><a href="<?php echo $baseurl;?>/news/add"><?php echo __('Add News Item');?></a></li>
                        <?php if ($menuItem === 'edit'): ?>
                            <li class="active"><a href="#"><?php echo __('Edit News Item');?></a></li>
                        <?php endif;
                    endif;
                break;

                case 'galaxies':
                ?>
                    <li id='liindex'><a href="<?php echo $baseurl;?>/galaxies/index"><?php echo __('List Galaxies');?></a></li>
                <?php
                    if ($isSiteAdmin):
                ?>
                        <li><?php echo $this->Form->postLink(__('Update Galaxies'), array('controller' => 'galaxies', 'action' => 'update'), null, __('Are you sure you want to reimport all galaxies from the submodule?')); ?></li>
                        <li><?php echo $this->Form->postLink(__('Force Update Galaxies'), array('controller' => 'galaxies', 'action' => 'update', 'force' => 1), null, __('Are you sure you want to drop and reimport all galaxies from the submodule?')); ?></li>
                <?php
                    endif;
                    if ($menuItem === 'viewGraph' || $menuItem === 'view_cluster'): ?>
                        <li><a href="<?php echo $baseurl;?>/galaxies/view/<?php echo h($galaxy_id); ?>"><?php echo __('View Galaxy');?></a></li>
                        <li id='liview_cluster'><a href="<?php echo $baseurl;?>/galaxy_clusters/view/<?php echo h($id); ?>"><?php echo __('View Cluster');?></a></li>
                        <li id='liviewGraph'><a href="<?php echo $baseurl;?>/galaxies/viewGraph/<?php echo h($id); ?>"><?php echo __('View Correlation Graph');?></a></li>
                <?php
                    endif;

                    if ($menuItem === 'view'):
                ?>
                        <li class="active"><a href="#"><?php echo __('View Galaxy');?></a></li>
                <?php
                    endif;
                break;
                case 'objectTemplates':
                ?>
                    <li id='liindex'><a href="<?php echo $baseurl;?>/objectTemplates/index"><?php echo __('List Object Templates');?></a></li>
                <?php
                    if ($isSiteAdmin):
                ?>
                    <li><?php echo $this->Form->postLink(__('Update Objects'), '/objectTemplates/update'); ?></li>
                <?php
                    endif;
                    if ($menuItem === 'view'):
                ?>
                        <li class="active"><a href="#"><?php echo __('View Object Template');?></a></li>
                <?php
                    endif;
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
