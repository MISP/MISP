<?php
if (!empty($me)) {
    if (Configure::read('MISP.home_logo')) {
        $logoPath = APP . 'files/img/custom/' . Configure::read('MISP.home_logo');
        if (file_exists($logoPath)) {
            $logoHtml = '<img src="' . $this->Image->base64($logoPath) . '" style="height:24px;" alt="' . __('Home') . '">';
        } else {
            $logoHtml =  __('Home');
        }
    } else {
        $logoHtml = __('Home');
    }

    // New approach how to define menu requirements. It takes ACLs from ACLComponent.
    $menu = array(
        array(
            'type' => 'root',
            'url' => empty($homepage['path']) ? $baseurl .'/' : $baseurl . h($homepage['path']),
            'html' => $logoHtml
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
                    'requirement' => $this->Acl->canAccess('events', 'add'),
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
                    'type' => 'separator'
                ),
                array(
                    'text' => __('List Collections'),
                    'url' => $baseurl . '/collections/index'
                ),
                [
                    'type' => 'separator'
                ],
                [
                    'text' => __('List Analyst Data'),
                    'url' => $baseurl . '/analyst_data/index'
                ],
                [
                    'type' => 'separator'
                ],
                array(
                    'text' => __('View Proposals'),
                    'url' => $baseurl . '/shadow_attributes/index/all:0'
                ),
                array(
                    'text' => __('Events with proposals'),
                    'url' => $baseurl . '/events/proposalEventIndex'
                ),
                array(
                    'url' => $baseurl . '/event_delegations/index/context:pending',
                    'text' => __('View delegation requests'),
                    'requirement' => $this->Acl->canAccess('event_delegations', 'index'),
                ),
                array(
                    'type' => 'separator'
                ),
                array(
                    'text' => __('List Tags'),
                    'url' => $baseurl . '/tags/index'
                ),
                array(
                    'text' => __('Add Tag'),
                    'url' => $baseurl . '/tags/add',
                    'requirement' => $this->Acl->canAccess('tags', 'add'),
                ),
                array(
                    'text' => __('List Tag Collections'),
                    'url' => $baseurl . '/tag_collections/index'
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
                    'type' => 'separator'
                ),
                array(
                    'text' => __('Export'),
                    'url' => $baseurl . '/events/export'
                ),
                array(
                    'text' => __('Automation'),
                    'url' => $baseurl . '/events/automation',
                    'requirement' => $this->Acl->canAccess('events', 'automation'),
                ),
                array(
                    'type' => 'separator',
                    'requirement' =>
                        Configure::read('MISP.enableEventBlocklisting') !== false &&
                        !$isSiteAdmin &&
                        $hostOrgUser
                ),
                array(
                    'text' => __('Blocklist Event'),
                    'url' => $baseurl . '/eventBlocklists/add',
                    'requirement' =>
                        Configure::read('MISP.enableEventBlocklisting') !== false &&
                        !$isSiteAdmin && $hostOrgUser
                ),
                array(
                    'text' => __('Manage Event Blocklists'),
                    'url' => $baseurl . '/eventBlocklists',
                    'requirement' =>
                        Configure::read('MISP.enableEventBlocklisting') !== false &&
                        !$isSiteAdmin && $hostOrgUser
                )
            )
        ),
        array(
            'type' => 'root',
            'text' => __('Dashboard'),
            'url' => $baseurl . '/dashboards'
        ),
        array(
            'type' => 'root',
            'text' => __('Galaxies'),
            'url' => $baseurl . '/galaxies/index',
            'children' => array(
                array(
                    'text' => __('List Galaxies'),
                    'url' => $baseurl . '/galaxies/index'
                ),
                array(
                    'text' => __('List Relationships'),
                    'url' => $baseurl . '/galaxy_cluster_relations/index'
                ),
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
                    'text' => __('Signature Allowedlist'),
                    'url' => $baseurl . '/admin/allowedlists/index',
                    'requirement' => $isAclRegexp
                ),
                array(
                    'text' => __('Signature Allowedlist'),
                    'url' => $baseurl . '/allowedlists/index',
                    'requirement' => !$isAclRegexp
                ),
                array(
                    'text' => __('Warninglists'),
                    'url' => $baseurl . '/warninglists/index'
                ),
                array(
                    'text' => __('Noticelists'),
                    'url' => $baseurl . '/noticelists/index'
                ),
                array(
                    'text' => __('Correlation Exclusions'),
                    'url' => $baseurl . '/correlation_exclusions/index',
                    'requirement' => $this->Acl->canAccess('correlation_exclusions', 'index'),
                )
            )
        ),
        array(
            'type' => 'root',
            'text' => __('Global Actions'),
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
                    'text' => __('My Settings'),
                    'url' => $baseurl . '/user_settings/index/user_id:me'
                ),
                array(
                    'text' => __('Set Setting'),
                    'url' => $baseurl . '/user_settings/setSetting'
                ),
                array(
                    'text' => __('Organisations'),
                    'url' => $baseurl . '/organisations/index',
                    'requirement' => $this->Acl->canAccess('organisations', 'index'),
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
                    'requirement' => $this->Acl->canAccess('sharing_groups', 'add'),
                ),
                array(
                    'text' => __('List Sharing Groups Blueprints'),
                    'url' => $baseurl . '/sharing_group_blueprints/index',
                    'requirement' => $this->Acl->canAccess('sharing_group_blueprints', 'index'),
                ),
                array(
                    'text' => __('Add Sharing Group Blueprint'),
                    'url' => $baseurl . '/sharing_group_blueprints/add',
                    'requirement' => $this->Acl->canAccess('sharing_group_blueprints', 'add'),
                ),
                array(
                    'type' => 'separator'
                ),
                array(
                    'text' => __('Decaying Models Tool'),
                    'url' => $baseurl . '/decayingModel/decayingTool',
                    'requirement' => $isAdmin
                ),
                array(
                    'text' => __('List Decaying Models'),
                    'url' => $baseurl . '/decayingModel/index',
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
                    'type' => 'separator',
                    'requirement' => $this->Acl->canAccess('threads', 'index'),
                ),
                array(
                    'text' => __('List Discussions'),
                    'url' => $baseurl . '/threads/index',
                    'requirement' => $this->Acl->canAccess('threads', 'index'),
                ),
                array(
                    'text' => __('Start Discussion'),
                    'url' => $baseurl . '/posts/add',
                    'requirement' => $this->Acl->canAccess('posts', 'add'),
                )
            )
        ),
        array(
            'type' => 'root',
            'text' => __('Sync Actions'),
            'requirement' =>  $isAclSync || $isAdmin || $hostOrgUser,
            'children' => array(
                array(
                    'text' => __('Create Sync Config'),
                    'url' => $baseurl . '/servers/createSync',
                    'requirement' => $isAclSync && !$isSiteAdmin
                ),
                array(
                    'text' => __('Remote Servers'),
                    'url' => $baseurl . '/servers/index',
                    'requirement' => $this->Acl->canAccess('servers', 'index'),
                ),
                array(
                    'text' => __('Feeds'),
                    'url' => $baseurl . '/feeds/index',
                    'requirement' => $this->Acl->canAccess('feeds', 'index'),
                ),
                array(
                    'text' => __('SightingDB'),
                    'url' => $baseurl . '/sightingdb/index',
                    'requirement' => $this->Acl->canAccess('sightingdb', 'index'),
                ),
                array(
                    'text' => __('Communities'),
                    'url' => $baseurl . '/communities/index',
                    'requirement' => $this->Acl->canAccess('communities', 'index'),
                ),
                array(
                    'text' => __('Cerebrates'),
                    'url' => $baseurl . '/cerebrates/index',
                    'requirement' => $this->Acl->canAccess('cerebrates', 'index'),
                ),
                array(
                    'text' => __('TAXII Servers'),
                    'url' => $baseurl . '/TaxiiServers/index',
                    'requirement' => $this->Acl->canAccess('taxiiServers', 'index'),
                ),
                array(
                    'text' => __('Event ID translator'),
                    'url' => '/servers/idTranslator',
                    'requirement' => $this->Acl->canAccess('servers', 'idTranslator')
                )
            )
        ),
        array(
            'type' => 'root',
            'text' => __('Administration'),
            'url' => $baseurl . '/servers/serverSettings',
            'requirement' => $isAdmin,
            'children' => array(
                array(
                    'text' => __('List Users'),
                    'url' => $baseurl . '/admin/users/index'
                ),
                array(
                    'text' => __('List Auth Keys'),
                    'url' => $baseurl . '/auth_keys/index'
                ),
                array(
                    'text' => __('List User Settings'),
                    'url' => $baseurl . '/user_settings/index/user_id:all'
                ),
                array(
                    'text' => __('Set User Setting'),
                    'url' => $baseurl . '/user_settings/setSetting'
                ),
                array(
                    'text' => __('Add User'),
                    'url' => $baseurl . '/admin/users/add',
                    'requirement' => $this->Acl->canAccess('users', 'admin_add'),
                ),
                array(
                    'text' => __('Contact Users'),
                    'url' => $baseurl . '/admin/users/email'
                ),
                array(
                    'text' => __('User Registrations'),
                    'url' => $baseurl . '/users/registrations',
                    'requirement' => $this->Acl->canAccess('users', 'registrations'),
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
                    'url' => $baseurl . '/admin/organisations/add',
                    'requirement' => $this->Acl->canAccess('organisations', 'admin_add'),
                ),
                array(
                    'type' => 'separator'
                ),
                array(
                    'text' => __('List Roles'),
                    'url' => $baseurl . '/roles/index'
                ),
                array(
                    'text' => __('Add Roles'),
                    'url' => $baseurl . '/admin/roles/add',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin,
                ),
                array(
                    'text' => __('Server Settings & Maintenance'),
                    'url' => $baseurl . '/servers/serverSettings',
                    'requirement' => $isSiteAdmin
                ),
                [
                    'text' => __('Benchmarking'),
                    'url' => $baseurl . '/benchmarks/index',
                    'requirement' => $isSiteAdmin && Configure::read('Plugin.Benchmarking_enable')
                ],
                array(
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'text' => __('Jobs'),
                    'url' => $baseurl . '/jobs/index',
                    'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                ),
                array(
                    'text' => __('Scheduled Tasks'),
                    'url' => $baseurl . '/tasks',
                    'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                ),
                array(
                    'html' => sprintf(
                        '<span style="display: flex;"><span>%s</span></span>',
                        __('Workflows')
                    ),
                    'url' => $baseurl . '/workflows/triggers',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'text' => __('Event Block Rules'),
                    'url' => $baseurl . '/servers/eventBlockRule',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'text' => __('Event Blocklists'),
                    'url' => $baseurl . '/eventBlocklists',
                    'requirement' => Configure::read('MISP.enableEventBlocklisting') !== false && $isSiteAdmin
                ),
                array(
                    'text' => __('Org Blocklists'),
                    'url' => $baseurl . '/orgBlocklists',
                    'requirement' => Configure::read('MISP.enableOrgBlocklisting') !== false && $isSiteAdmin
                ),
                [
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin
                ],
                [
                    'text' => __('Top Correlations'),
                    'url' => $baseurl . '/correlations/top',
                    'requirement' => $isSiteAdmin
                ],
                [
                    'html' => sprintf(
                        '<span style="display: flex;"><span>%s</span></span>',
                        __('Over-correlating values')
                    ),
                    'url' => $baseurl . '/correlations/overCorrelations',
                    'requirement' => $isSiteAdmin
                ]
            )
        ),
        array(
            'type' => 'root',
            'text' => __('Logs'),
            'requirement' => $isAclAudit,
            'children' => array(
                array(
                    'text' => __('Application Logs'),
                    'url' => $baseurl . '/logs/index'
                ),
                array(
                    'text' => __('Audit Logs'),
                    'url' => $baseurl . '/admin/audit_logs/index',
                    'requirement' => Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index'),
                ),
                array(
                    'text' => __('Access Logs'),
                    'url' => $baseurl . '/admin/access_logs/index',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'text' => __('Search Logs'),
                    'url' => $baseurl . '/admin/logs/search',
                    'requirement' => $this->Acl->canAccess('logs', 'admin_search')
                )
            )
        ),
        array(
            'type' => 'root',
            'text' => __('API'),
            'children' => array(
                array(
                    'text' => __('OpenAPI'),
                    'url' => $baseurl . '/api/openapi'
                ),
                array(
                    'text' => __('REST client'),
                    'url' => $baseurl . '/api/rest',
                    'requirement' => $this->Acl->canAccess('api', 'rest')
                )
            )
        )
    );
    $menu_right = array(
        array(
            'type' => 'root',
            'url' => '#',
            'html' => sprintf(
                '<span class="fas fa-star %s" id="setHomePage" title="%s" role="img" aria-label="%s" data-current-page="%s"></span>',
                (!empty($homepage['path']) && $homepage['path'] === $this->here) ? 'orange' : '',
                __('Set the current page as your home page in MISP'),
                __('Set the current page as your home page in MISP'),
                h($this->here)
            )
        ),
        array(
            'type' => 'root',
            'url' => empty($homepage['path']) ? $baseurl : $baseurl . h($homepage['path']),
            'html' => '<span class="logoBlueStatic bold" id="smallLogo">MISP</span>'
        ),
        [
            'type' => 'root',
            'url' => Configure::read('MISP.menu_custom_right_link'),
            'html' => Configure::read('MISP.menu_custom_right_link_html'),
            'requirement' => !empty(Configure::read('MISP.menu_custom_right_link')),
        ],
        array(
            'type' => 'root',
            'url' => $baseurl . '/users/view/me',
            'html' => sprintf(
                '<span class="white" title="%s">%s%s&nbsp;&nbsp;&nbsp;%s</span>',
                h($me['email']),
                $this->UserName->prepend($me['email']),
                h($this->UserName->convertEmailToName($me['email'])),
                isset($hasNotifications) ? sprintf(
                    '<i class="fa fa-envelope %s" role="img" aria-label="%s"></i>',
                    $hasNotifications ? 'red' : 'white',
                    __('Notifications')
                ) : ''
            )
        ),
        array(
            'url' => $baseurl . '/users/logout',
            'text' => __('Log out'),
            'requirement' => empty(Configure::read('Plugin.CustomAuth_disable_logout'))
        )
    );
}
$isHal = date('Y-10-31') == date('Y-m-d');
if ($isHal) {
    $tmp = [
        'type' => 'root',
        'url'=> '#',
        'html' => '<span onclick="toggleHal()" class="fa-stack fa-1x">
                       <i class="fas fa-broom fa-stack-1x"></i>
                       <i class="fas fa-cat fa-stack-1x fa-flip-horizontal" style="bottom: 8px; left: 2px;"></i>
                   </span>'
    ];
    if (isset($menu_right)) {
        $menu_right = array_merge([$tmp], $menu_right);
    }
}
?>
<div id="topBar" class="navbar navbar-inverse <?= isset($debugMode) ? $debugMode : 'debugOff' ?>" style="z-index:100;">
  <div class="navbar-inner">
    <ul class="nav">
        <?php
        if (isset($menu)) {
            foreach ($menu as $root_element) {
                echo $this->element('/genericElements/GlobalMenu/global_menu_root', array('data' => $root_element));
            }
        }
        ?>
    </ul>
    <ul class="nav pull-right">
        <?php
            if (isset($menu_right)) {
                foreach ($menu_right as $root_element) {
                    echo $this->element('/genericElements/GlobalMenu/global_menu_root', array('data' => $root_element));
                }
            }
        ?>
    </ul>
</div>
  <?php
    if ($isHal) {
        echo $this->element('hal-ee');
    }
  ?>
