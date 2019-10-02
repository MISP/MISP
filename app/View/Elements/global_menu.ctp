<?php
    if (!empty($me)) {
        $menu = array(
            array(
                'type' => 'root',
                'url' => $baseurl . '/',
                'html' => (Configure::read('MISP.home_logo') ?  $logo = '<img src="' . $baseurl . '/img/custom/' . Configure::read('MISP.home_logo') . '" style="height:24px;">' : __('Home'))
            ),
            array(
                'type' => 'root',
                'text' => __('Event Actions'),
                'children' => array(
                    array(
                        'text' => __('List Events'),
                        'url' => '/events/index'
                    ),
                    array(
                        'text' => __('Add Event'),
                        'url' => '/events/add',
                        'requirement' => $isAclAdd
                    ),
                    array(
                        'text' => __('List Attributes'),
                        'url' => '/attributes/index'
                    ),
                    array(
                        'text' => __('Search Attributes'),
                        'url' => '/attributes/search'
                    ),
                    array(
                        'text' => __('REST client'),
                        'url' => '/servers/rest'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('View Proposals'),
                        'url' => '/shadow_attributes/index/all:0'
                    ),
                    array(
                        'text' => __('Events with proposals'),
                        'url' => '/events/proposalEventIndex'
                    ),
                    array(
                        'url' => '/event_delegations/index/context:pending',
                        'text' => __('View delegation requests')
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Tags'),
                        'url' => '/tags/index'
                    ),
                    array(
                        'text' => __('List Tag Collections'),
                        'url' => '/tag_collections/index'
                    ),
                    array(
                        'text' => __('Add Tag'),
                        'url' => '/tags/add',
                        'requirement' => $isAclTagEditor
                    ),
                    array(
                        'text' => __('List Taxonomies'),
                        'url' => '/taxonomies/index'
                    ),
                    array(
                        'text' => __('List Templates'),
                        'url' => '/templates/index'
                    ),
                    array(
                        'text' => __('Add Template'),
                        'url' => '/templates/add',
                        'requirement' => $isAclTemplate
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('Export'),
                        'url' => '/events/export'
                    ),
                    array(
                        'text' => __('Automation'),
                        'url' => '/events/automation',
                        'requirement' => $isAclAuth
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Galaxies'),
                'url' => '/galaxies/index',
                'children' => array(
                    array(
                        'text' => __('List Galaxies'),
                        'url' => '/galaxies/index'
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Input Filters'),
                'children' => array(
                    array(
                        'text' => __('Import Regexp'),
                        'url' => '/admin/regexp/index',
                        'requirement' => $isAclRegexp
                    ),
                    array(
                        'text' => __('Import Regexp'),
                        'url' => '/regexp/index',
                        'requirement' => !$isAclRegexp
                    ),
                    array(
                        'text' => __('Signature Whitelist'),
                        'url' => '/admin/whitelists/index',
                        'requirement' => $isAclRegexp
                    ),
                    array(
                        'text' => __('Signature Whitelist'),
                        'url' => '/whitelists/index',
                        'requirement' => !$isAclRegexp
                    ),
                    array(
                        'text' => __('List Warninglists'),
                        'url' => '/warninglists/index'
                    ),
                    array(
                        'text' => __('List Noticelists'),
                        'url' => '/noticelists/index'
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Global Actions'),
                'url' => '/users/dashboard',
                'children' => array(
                    array(
                        'text' => __('News'),
                        'url' => '/news'
                    ),
                    array(
                        'text' => __('My Profile'),
                        'url' => '/users/view/me'
                    ),
                    array(
                        'text' => __('Dashboard'),
                        'url' => '/users/dashboard'
                    ),
                    array(
                        'text' => __('Organisations'),
                        'url' => '/organisations/index',
                        'requirement' => $isAclSharingGroup || empty(Configure::read('Security.hide_organisation_index_from_users'))
                    ),
                    array(
                        'text' => __('Role Permissions'),
                        'url' => '/roles/index'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Object Templates'),
                        'url' => '/objectTemplates/index'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Sharing Groups'),
                        'url' => '/sharing_groups/index'
                    ),
                    array(
                        'text' => __('Add Sharing Group'),
                        'url' => '/sharing_groups/add',
                        'requirement' => $isAclSharingGroup
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('Decaying Models Tool'),
                        'url' => '/decayingModel/decayingTool',
                        'requirement' => $isAdmin
                    ),
                    array(
                        'text' => __('Decaying Models'),
                        'url' => '/decayingModel/index',
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('User Guide'),
                        'url' => 'https://www.circl.lu/doc/misp/'
                    ),
                    array(
                        'text' => __('Categories & Types'),
                        'url' => '/pages/display/doc/categories_and_types'
                    ),
                    array(
                        'text' => __('Terms & Conditions'),
                        'url' => '/users/terms'
                    ),
                    array(
                        'text' => __('Statistics'),
                        'url' => '/users/statistics'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Discussions'),
                        'url' => '/threads/index'
                    ),
                    array(
                        'text' => __('Start Discussion'),
                        'url' => '/posts/add'
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Sync Actions'),
                'requirement' =>  ($isAclSync || $isAdmin || $hostOrgUser),
                'children' => array(
                    array(
                        'text' => __('Create Sync Config'),
                        'url' => '/servers/createSync',
                        'requirement' => ($isAclSync && !$isSiteAdmin)
                    ),
                    array(
                        'text' => __('Import Server Settings'),
                        'url' => '/servers/import',
                        'requirement' => ($isSiteAdmin)
                    ),
                    array(
                        'text' => __('List Servers'),
                        'url' => '/servers/index',
                        'requirement' => ($isAclSync || $isAdmin)
                    ),
                    array(
                        'text' => __('List Feeds'),
                        'url' => '/feeds/index',
                        'requirement' => ($isSiteAdmin || $hostOrgUser)
                    ),
                    array(
                        'text' => __('Search Feed Caches'),
                        'url' => '/feeds/searchCaches',
                        'requirement' => ($isSiteAdmin || $hostOrgUser)
                    ),
                    array(
                        'text' => __('List Communities'),
                        'url' => '/communities/index',
                        'requirement' => ($isSiteAdmin)
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Administration'),
                'url' => '/servers/serverSettings',
                'requirement' =>  ($isAdmin),
                'children' => array(
                    array(
                        'text' => __('List Users'),
                        'url' => '/admin/users/index'
                    ),
                    array(
                        'text' => __('Add User'),
                        'url' => '/admin/users/add'
                    ),
                    array(
                        'text' => __('Contact Users'),
                        'url' => '/admin/users/email'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Organisations'),
                        'url' => '/organisations/index'
                    ),
                    array(
                        'text' => __('Add Organisations'),
                        'url' => '/admin/organisations/add'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Roles'),
                        'url' => '/admin/roles/index'
                    ),
                    array(
                        'text' => __('Add Roles'),
                        'url' => '/admin/roles/add',
                        'requirement' => $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                    ),
                    array(
                        'text' => __('Server Settings & Maintenance'),
                        'url' => '/servers/serverSettings',
                        'requirement' => $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Jobs'),
                        'url' => '/jobs/index',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Scheduled Tasks'),
                        'url' => '/tasks',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Blacklist Event'),
                        'url' => '/eventBlacklists/add',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Manage Event Blacklists'),
                        'url' => '/eventBlacklists',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Blacklist Organisation'),
                        'url' => '/orgBlacklists/add',
                        'requirement' => Configure::read('MISP.enableOrgBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Manage Org Blacklists'),
                        'url' => '/orgBlacklists',
                        'requirement' => Configure::read('MISP.enableOrgBlacklisting') !== false && $isSiteAdmin
                    ),
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Audit'),
                'requirement' =>  ($isAclAudit),
                'children' => array(
                    array(
                        'text' => __('List Logs'),
                        'url' => '/admin/logs/index'
                    ),
                    array(
                        'text' => __('Search Logs'),
                        'url' => '/admin/logs/search'
                    )
                )
            )
        );
        $menu_right = array(
            array(
                'type' => 'root',
                'url' => $baseurl . '/',
                'html' => '<span class="logoBlueStatic bold" id="smallLogo">MISP</span>'
            ),
            array(
                'type' => 'root',
                'url' => '/users/dashboard',
                'html' => sprintf(
                    '<span class="white" title="%s">%s%s&nbsp;&nbsp;&nbsp;%s</span>',
                    h($me['email']),
                    $this->UserName->prepend($me['email']),
                    h($loggedInUserName),
                    sprintf(
                        '<i class="fa fa-envelope %s"></i>',
                        (($notifications['total'] == 0) ? 'white' : 'red')
                    )
                )
            ),
            array(
                'url' => h(Configure::read('Plugin.CustomAuth_custom_logout')),
                'text' => __('Log out'),
                'requirement' => (Configure::read('Plugin.CustomAuth_custom_logout') && empty(Configure::read('Plugin.CustomAuth_disable_logout')))
            ),
            array(
                'url' => '/users/logout',
                'text' => __('Log out'),
                'requirement' => (!$externalAuthUser && empty(Configure::read('Plugin.CustomAuth_disable_logout')))
            )
        );
    }
?>
<div id="topBar" class="navbar navbar-inverse <?php echo $debugMode;?>" style="z-index: 20;">
  <div class="navbar-inner">
    <ul class="nav">
        <?php
            if (!empty($menu)) {
                foreach ($menu as $root_element) {
                    echo $this->element('/genericElements/GlobalMenu/global_menu_root', array('data' => $root_element));
                }
            }
        ?>
    </ul>
    <ul class="nav pull-right">
        <?php
            if (!empty($menu_right)) {
                foreach ($menu_right as $root_element) {
                    echo $this->element('/genericElements/GlobalMenu/global_menu_root', array('data' => $root_element));
                }
            }
        ?>
    </ul>
  </div>
</div>
<input type="hidden" class="keyboardShortcutsConfig" value="/shortcuts/global_menu.json" />
