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
                        'url' => $baseurl . '/events/index'
                    ),
                    array(
                        'text' => __('Add Event'),
                        'url' => $baseurl . '/events/add',
                        'requirement' => $isAclAdd
                    ),
                    array(
                        'text' => __('List Attributes'),
                        'url' => $baseurl . '/attributes/index'
                    ),
                    array(
                        'text' => __('Search Attributes'),
                        'url' => $baseurl . '/attributes/search'
                    ),
                    array(
                        'text' => __('REST client'),
                        'url' => $baseurl . '/servers/rest'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('View Proposals'),
                        'url' => $baseurl . '/shadow_attributes/index'
                    ),
                    array(
                        'text' => __('Events with proposals'),
                        'url' => $baseurl . '/events/proposalEventIndex'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Tags'),
                        'url' => $baseurl . '/tags/index'
                    ),
                    array(
                        'text' => __('List Tag Collections'),
                        'url' => $baseurl . '/tag_collections/index'
                    ),
                    array(
                        'text' => __('Add Tag'),
                        'url' => $baseurl . '/tags/add',
                        'requirement' => $isAclTagEditor
                    ),
                    array(
                        'text' => __('List Taxonomies'),
                        'url' => $baseurl . '/taxonomies/index'
                    ),
                    array(
                        'text' => __('List Templates'),
                        'url' => $baseurl . '/templates/index'
                    ),
                    array(
                        'text' => __('Add Template'),
                        'url' => $baseurl . '/templates/add',
                        'requirement' => $isAclTemplate
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('Export'),
                        'url' => $baseurl . '/events/export'
                    ),
                    array(
                        'text' => __('Automation'),
                        'url' => $baseurl . '/events/automation',
                        'requirement' => $isAclAuth
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Galaxies'),
                'url' => $baseurl . '/galaxies/index',
                'children' => array(
                    array(
                        'text' => __('List Galaxies'),
                        'url' => $baseurl . '/galaxies/index'
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Input Filters'),
                'children' => array(
                    array(
                        'text' => __('Import Regexp'),
                        'url' => $baseurl . '/admin/regexp/index',
                        'requirement' => $isAclRegexp
                    ),
                    array(
                        'text' => __('Import Regexp'),
                        'url' => $baseurl . '/regexp/index',
                        'requirement' => !$isAclRegexp
                    ),
                    array(
                        'text' => __('Signature Whitelist'),
                        'url' => $baseurl . '/admin/whitelists/index',
                        'requirement' => $isAclRegexp
                    ),
                    array(
                        'text' => __('Signature Whitelist'),
                        'url' => $baseurl . '/whitelists/index',
                        'requirement' => !$isAclRegexp
                    ),
                    array(
                        'text' => __('List Warninglists'),
                        'url' => $baseurl . '/warninglists/index'
                    ),
                    array(
                        'text' => __('List Noticelists'),
                        'url' => $baseurl . '/noticelists/index'
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Global Actions'),
                'url' => $baseurl . '/users/dashboard',
                'children' => array(
                    array(
                        'text' => __('News'),
                        'url' => $baseurl . '/news'
                    ),
                    array(
                        'text' => __('My Profile'),
                        'url' => $baseurl . '/users/view/me'
                    ),
                    array(
                        'text' => __('Dashboard'),
                        'url' => $baseurl . '/users/dashboard'
                    ),
                    array(
                        'text' => __('Organisations'),
                        'url' => $baseurl . '/organisations/index',
                        'requirement' => $isAclSharingGroup || empty(Configure::read('Security.hide_organisation_index_from_users'))
                    ),
                    array(
                        'text' => __('Role Permissions'),
                        'url' => $baseurl . '/roles/index'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Object Templates'),
                        'url' => $baseurl . '/objectTemplates/index'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Sharing Groups'),
                        'url' => $baseurl . '/sharing_groups/index'
                    ),
                    array(
                        'text' => __('Add Sharing Group'),
                        'url' => $baseurl . '/sharing_groups/add',
                        'requirement' => $isAclSharingGroup
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
                        'url' => $baseurl . '/pages/display/doc/categories_and_types'
                    ),
                    array(
                        'text' => __('Terms & Conditions'),
                        'url' => $baseurl . '/users/terms'
                    ),
                    array(
                        'text' => __('Statistics'),
                        'url' => $baseurl . '/users/statistics'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Discussions'),
                        'url' => $baseurl . '/threads/index'
                    ),
                    array(
                        'text' => __('Start Discussion'),
                        'url' => $baseurl . '/posts/add'
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
                        'url' => $baseurl . '/servers/index',
                        'requirement' => ($isAclSync || $isAdmin)
                    ),
                    array(
                        'text' => __('List Feeds'),
                        'url' => $baseurl . '/feeds/index',
                        'requirement' => ($isSiteAdmin || $hostOrgUser)
                    ),
                    array(
                        'text' => __('Search Feed Caches'),
                        'url' => $baseurl . '/feeds/searchCaches',
                        'requirement' => ($isSiteAdmin || $hostOrgUser)
                    )
                )
            ),
            array(
                'type' => 'root',
                'text' => __('Administration'),
                'url' => $baseurl . '/servers/serverSettings',
                'requirement' =>  ($isAdmin),
                'children' => array(
                    array(
                        'text' => __('List Users'),
                        'url' => $baseurl . '/admin/users/index'
                    ),
                    array(
                        'text' => __('Add User'),
                        'url' => $baseurl . '/admin/users/add'
                    ),
                    array(
                        'text' => __('Contact Users'),
                        'url' => $baseurl . '/admin/users/email'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Organisations'),
                        'url' => $baseurl . '/organisations/index'
                    ),
                    array(
                        'text' => __('Add Organisations'),
                        'url' => $baseurl . '/admin/organisations/add'
                    ),
                    array(
                        'type' => 'separator'
                    ),
                    array(
                        'text' => __('List Roles'),
                        'url' => $baseurl . '/admin/roles/index'
                    ),
                    array(
                        'text' => __('Add Roles'),
                        'url' => $baseurl . '/admin/roles/add',
                        'requirement' => $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => $isSiteAdmin
                    ),
                    array(
                        'text' => __('Server Settings & Maintenance'),
                        'url' => $baseurl . '/servers/serverSettings',
                        'requirement' => $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Jobs'),
                        'url' => $baseurl . '/jobs/index',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Scheduled Tasks'),
                        'url' => $baseurl . '/tasks',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Blacklist Event'),
                        'url' => $baseurl . '/eventBlacklists/add',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Manage Event Blacklists'),
                        'url' => $baseurl . '/eventBlacklists',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'type' => 'separator',
                        'requirement' => Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Blacklist Organisation'),
                        'url' => $baseurl . '/orgBlacklists/add',
                        'requirement' => Configure::read('MISP.enableOrgBlacklisting') !== false && $isSiteAdmin
                    ),
                    array(
                        'text' => __('Manage Org Blacklists'),
                        'url' => $baseurl . '/orgBlacklists',
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
                        'url' => $baseurl . '/admin/logs/index'
                    ),
                    array(
                        'text' => __('Search Logs'),
                        'url' => $baseurl . '/admin/logs/search'
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
                'url' => $baseurl . '/users/dashboard',
                'html' => sprintf(
                    '<span class="white" title="%s">%s&nbsp;&nbsp;&nbsp;%s</span>',
                    h($me['email']),
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
                'url' => $baseurl . '/users/logout',
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
