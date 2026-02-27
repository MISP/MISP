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

    // Build bookmarks
    $topbarBookmarks = [];
    foreach ($bookmarks as $bookmark) {
        $topbarBookmarks[] = [
            'html' => sprintf('<span title="%s"><i class="fas fa-link fa-fw"></i> %s</span>', h($bookmark['Bookmark']['comment']), h($bookmark['Bookmark']['name'])),
            'url' => h($bookmark['Bookmark']['url']),
        ];
    }
    $topbarBookmarks[] = ['type' => 'separator'];
    $topbarBookmarks[] = [
        'html' => sprintf('<span id="bookmarkThisPageContainer" data-current-page="%s"><i class="fas fa-plus fa-fw"></i> %s</span>',
           $baseurl .  h($this->here),
            __('Bookmark this page')
        ),
        'requirement' => $this->Acl->canAccess('bookmarks', 'add'),
    ];
    $topbarBookmarks[] = [
        'html' => sprintf('<i class="fas fa-cogs fa-fw"></i> %s', __('Manage Bookmarks')),
        'url' => $baseurl . '/bookmarks/index',
        'requirement' => $this->Acl->canAccess('bookmarks', 'add'),
    ];

    $menu = array(
        // 1. Home
        array(
            'type' => 'root',
            'url' => empty($homepage['path']) ? $baseurl .'/' : $baseurl . h($homepage['path']),
            'html' => $logoHtml
        ),
        // 2. Events
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-clipboard-list fa-fw"></i> ',
            'text' => __('Events'),
            'children' => array(

                array(
                    'html' => '<i class="fas fa-list fa-fw"></i> ' . __('Event Index'),
                    'url' => $baseurl . '/events/index'
                ),
                array(
                    'type' => 'separator'
                ),
                // Events Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-clipboard-list fa-fw"></i> ' . __('Events'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-list fa-fw"></i> ' . __('List'),
                            'url' => $baseurl . '/events/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-plus fa-fw"></i> ' . __('Add'),
                            'url' => $baseurl . '/events/add',
                            'requirement' => $this->Acl->canAccess('events', 'add'),
                        ),
                    )
                ),
                // Attributes Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-tags fa-fw"></i> ' . __('Attributes'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-list fa-fw"></i> ' . __('List'),
                            'url' => $baseurl . '/attributes/index'
                        ),

                        array(
                            'html' => '<i class="fas fa-search fa-fw"></i> ' . __('Search'),
                            'url' => $baseurl . '/attributes/search'
                        ),
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                array(
                    'html' => '<i class="fas fa-layer-group fa-fw"></i> ' . __('Collections'),
                    'url' => $baseurl . '/collections/index'
                ),
                [
                    'html' => '<i class="fas fa-file-alt fa-fw"></i> ' . __('Event Reports'),
                    'url' => $baseurl . '/event_reports/index'
                ],
                [
                    'html' => '<i class="fas fa-chart-line fa-fw"></i> ' . __('Analyst Data'),
                    'url' => $baseurl . '/analyst_data/index'
                ],
                array(
                    'type' => 'separator'
                ),
                // Proposals Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-comment-dots fa-fw"></i> ' . __('Proposals'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-eye fa-fw"></i> ' . __('View'),
                            'url' => $baseurl . '/shadow_attributes/index/all:0'
                        ),
                        array(
                            'html' => '<i class="fas fa-calendar-check fa-fw"></i> ' . __('Events with proposals'),
                            'url' => $baseurl . '/events/proposalEventIndex'
                        ),
                        array(
                            'url' => $baseurl . '/event_delegations/index/context:pending',
                            'html' => '<i class="fas fa-handshake fa-fw"></i> ' . __('Delegation requests'),
                            'requirement' => $this->Acl->canAccess('event_delegations', 'index'),
                        ),
                    )
                ),
                array(
                    'type' => 'separator',
                    'requirement' =>
                        Configure::read('MISP.enableEventBlocklisting') !== false &&
                        !$isSiteAdmin &&
                        $hostOrgUser
                ),
                // Blocklisting Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-ban fa-fw"></i> ' . __('Blocklisting'),
                    'requirement' =>
                        Configure::read('MISP.enableEventBlocklisting') !== false &&
                        !$isSiteAdmin &&
                        $hostOrgUser,
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-plus-circle fa-fw"></i> ' . __('Blocklist Event'),
                            'url' => $baseurl . '/eventBlocklists/add',
                        ),
                        array(
                            'html' => '<i class="fas fa-list-alt fa-fw"></i> ' . __('Manage Blocklists'),
                            'url' => $baseurl . '/eventBlocklists',
                        )
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                array(
                    'html' => '<i class="fas fa-tachometer-alt fa-fw"></i> ' . __('Dashboards'),
                    'url' => $baseurl . '/dashboards'
                ),
                array(
                    'html' => '<i class="fas fa-chart-pie fa-fw"></i> ' . __('Statistics'),
                    'url' => $baseurl . '/users/statistics'
                )
            )
        ),
        // 3. Data Models
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-drafting-compass fa-fw"></i> ',
            'text' => __('Data Models'),
            'children' => array(
                // Tags & Taxonomies Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-tags fa-fw"></i> ' . __('Tags & Taxonomies'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-tag fa-fw"></i> ' . __('List Tags'),
                            'url' => $baseurl . '/tags/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-plus fa-fw"></i> ' . __('Add Tag'),
                            'url' => $baseurl . '/tags/add',
                            'requirement' => $this->Acl->canAccess('tags', 'add'),
                        ),
                        array(
                            'html' => '<i class="fas fa-tags fa-fw"></i> ' . __('List Tag Collections'),
                            'url' => $baseurl . '/tag_collections/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-sitemap fa-fw"></i> ' . __('Tag Taxonomies'),
                            'url' => $baseurl . '/taxonomies/index'
                        ),
                    )
                ),
                // Galaxies Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-star fa-fw"></i> ' . __('Galaxies'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-star fa-fw"></i> ' . __('List Galaxies'),
                            'url' => $baseurl . '/galaxies/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-project-diagram fa-fw"></i> ' . __('List Galaxy Relationships'),
                            'url' => $baseurl . '/galaxy_cluster_relations/index'
                        ),
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                // Decaying Models Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-hourglass-half fa-fw"></i> ' . __('Decaying Models'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-hourglass-half fa-fw"></i> ' . __('Decaying Models Tool'),
                            'url' => $baseurl . '/decayingModel/decayingTool',
                            'requirement' => $isAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-list-ol fa-fw"></i> ' . __('List Decaying Models'),
                            'url' => $baseurl . '/decayingModel/index',
                        ),
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                // Templates Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-file-code fa-fw"></i> ' . __('Templates'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-file-code fa-fw"></i> ' . __('List Templates'),
                            'url' => $baseurl . '/templates/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-cubes fa-fw"></i> ' . __('List Object Templates'),
                            'url' => $baseurl . '/objectTemplates/index'
                        ),
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                // Lists & Regex Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-list-ul fa-fw"></i> ' . __('Filters & Lists'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-exclamation-triangle fa-fw"></i> ' . __('Warninglists'),
                            'url' => $baseurl . '/warninglists/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-info-circle fa-fw"></i> ' . __('Noticelists'),
                            'url' => $baseurl . '/noticelists/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-code fa-fw"></i> ' . __('Import Regexp'),
                            'url' => $baseurl . '/admin/regexp/index',
                            'requirement' => $isAclRegexp
                        ),
                        array(
                            'html' => '<i class="fas fa-code fa-fw"></i> ' . __('Import Regexp'),
                            'url' => $baseurl . '/regexp/index',
                            'requirement' => !$isAclRegexp
                        ),
                        array(
                            'html' => '<i class="fas fa-check-circle fa-fw"></i> ' . __('Signature Allowedlist'),
                            'url' => $baseurl . '/admin/allowedlists/index',
                            'requirement' => $isAclRegexp
                        ),
                        array(
                            'html' => '<i class="fas fa-check-circle fa-fw"></i> ' . __('Signature Allowedlist'),
                            'url' => $baseurl . '/allowedlists/index',
                            'requirement' => !$isAclRegexp
                        ),
                        array(
                            'html' => '<i class="fas fa-filter fa-fw"></i> ' . __('Correlation Exclusions'),
                            'url' => $baseurl . '/correlation_exclusions/index',
                            'requirement' => $this->Acl->canAccess('correlation_exclusions', 'index'),
                        )
                    )
                )
            )
        ),
        // 4. Sync
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-sync fa-fw"></i> ',
            'text' => __('Sync'),
            'requirement' =>  $isAclSync || $isAdmin || $hostOrgUser,
            'children' => array(
                // Servers & Feeds Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-server fa-fw"></i> ' . __('Servers & Feeds'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-sync fa-fw"></i> ' . __('Create Sync Config'),
                            'url' => $baseurl . '/servers/createSync',
                            'requirement' => $isAclSync && !$isSiteAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-server fa-fw"></i> ' . __('Remote Servers'),
                            'url' => $baseurl . '/servers/index',
                            'requirement' => $this->Acl->canAccess('servers', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-rss fa-fw"></i> ' . __('Feeds'),
                            'url' => $baseurl . '/feeds/index',
                            'requirement' => $this->Acl->canAccess('feeds', 'index'),
                        ),
                    )
                ),
                // Sharing Groups Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-share-alt fa-fw"></i> ' . __('Sharing Groups'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-share-alt fa-fw"></i> ' . __('List Sharing Groups'),
                            'url' => $baseurl . '/sharing_groups/index'
                        ),
                        array(
                            'html' => '<i class="fas fa-plus fa-fw"></i> ' . __('Add Sharing Group'),
                            'url' => $baseurl . '/sharing_groups/add',
                            'requirement' => $this->Acl->canAccess('sharing_groups', 'add'),
                        ),
                        array(
                            'html' => '<i class="fas fa-drafting-compass fa-fw"></i> ' . __('List Sharing Groups Blueprints'),
                            'url' => $baseurl . '/sharing_group_blueprints/index',
                            'requirement' => $this->Acl->canAccess('sharing_group_blueprints', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-plus-square fa-fw"></i> ' . __('Add Sharing Group Blueprint'),
                            'url' => $baseurl . '/sharing_group_blueprints/add',
                            'requirement' => $this->Acl->canAccess('sharing_group_blueprints', 'add'),
                        ),
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                // Integrations Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-plug fa-fw"></i> ' . __('Integrations'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-users fa-fw"></i> ' . __('Communities'),
                            'url' => $baseurl . '/communities/index',
                            'requirement' => $this->Acl->canAccess('communities', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-network-wired fa-fw"></i> ' . __('Cerebrates'),
                            'url' => $baseurl . '/cerebrates/index',
                            'requirement' => $this->Acl->canAccess('cerebrates', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-cloud fa-fw"></i> ' . __('TAXII Servers'),
                            'url' => $baseurl . '/TaxiiServers/index',
                            'requirement' => $this->Acl->canAccess('taxiiServers', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-eye fa-fw"></i> ' . __('SightingDB'),
                            'url' => $baseurl . '/sightingdb/index',
                            'requirement' => $this->Acl->canAccess('sightingdb', 'index'),
                        ),
                    )
                ),
                array(
                    'html' => '<i class="fas fa-exchange-alt fa-fw"></i> ' . __('Event ID translator'),
                    'url' => '/servers/idTranslator',
                    'requirement' => $this->Acl->canAccess('servers', 'idTranslator')
                )
            )
        ),
        // 5. Administration
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-tools fa-fw"></i> ',
            'text' => __('Administration'),
            'requirement' => $isAdmin || $this->Acl->canAccess('organisations', 'index'),
            'children' => array(
                array(
                    'html' => '<i class="fas fa-cogs fa-fw"></i> ' . __('Server Settings & Maintenance'),
                    'url' => $baseurl . '/servers/serverSettings',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin
                ),
                // Users & Orgs Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-users-cog fa-fw"></i> ' . __('Users & Orgs'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-user fa-fw"></i> ' . __('List Users'),
                            'url' => $baseurl . '/admin/users/index',
                            'requirement' => $isAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-user-plus fa-fw"></i> ' . __('Add User'),
                            'url' => $baseurl . '/admin/users/add',
                            'requirement' => $this->Acl->canAccess('users', 'admin_add'),
                        ),
                        array(
                            'html' => '<i class="fas fa-envelope fa-fw"></i> ' . __('Contact Users'),
                            'url' => $baseurl . '/admin/users/email',
                            'requirement' => $isAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-clipboard-list fa-fw"></i> ' . __('User Registrations'),
                            'url' => $baseurl . '/users/registrations',
                            'requirement' => $this->Acl->canAccess('users', 'registrations'),
                        ),
                        array(
                            'html' => '<i class="fas fa-building fa-fw"></i> ' . __('List Organisations'),
                            'url' => $baseurl . '/organisations/index',
                            'requirement' => $this->Acl->canAccess('organisations', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-plus-square fa-fw"></i> ' . __('Add Organisations'),
                            'url' => $baseurl . '/admin/organisations/add',
                            'requirement' => $this->Acl->canAccess('organisations', 'admin_add'),
                        ),
                    )
                ),
                // Roles & Permissions Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-user-shield fa-fw"></i> ' . __('Roles & Permissions'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-user-tag fa-fw"></i> ' . __('List Roles'),
                            'url' => $baseurl . '/roles/index',
                            'requirement' => $isAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-plus-circle fa-fw"></i> ' . __('Add Roles'),
                            'url' => $baseurl . '/admin/roles/add',
                            'requirement' => $isSiteAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-lock fa-fw"></i> ' . __('Role Permissions'),
                            'url' => $baseurl . '/roles/index',
                            'requirement' => $isAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-key fa-fw"></i> ' . __('List Auth Keys'),
                            'url' => $baseurl . '/auth_keys/index',
                            'requirement' => $isAdmin
                        ),
                    )
                ),
                array(
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin
                ),
                // System Jobs Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-cogs fa-fw"></i> ' . __('System Jobs'),
                    'children' => array(
                        array(
                            'html' => sprintf(
                                '<span style="display: flex;"><i class="fas fa-project-diagram fa-fw"></i>&nbsp;<span>%s</span></span>',
                                __('Workflows')
                            ),
                            'url' => $baseurl . '/workflows/triggers',
                            'requirement' => $isSiteAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-tasks fa-fw"></i> ' . __('Jobs'),
                            'url' => $baseurl . '/jobs/index',
                            'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-clock fa-fw"></i> ' . __('Scheduled Tasks'),
                            'url' => $baseurl . '/tasks',
                            'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin
                        ),
                        [
                            'html' => '<i class="fas fa-tachometer-alt fa-fw"></i> ' . __('Benchmarking'),
                            'url' => $baseurl . '/benchmarks/index',
                            'requirement' => $isSiteAdmin && Configure::read('Plugin.Benchmarking_enable')
                        ],
                    )
                ),
                array(
                    'type' => 'separator',
                    'requirement' => $isSiteAdmin
                ),
                // Blocklists & Rules Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-ban fa-fw"></i> ' . __('Blocklists & Rules'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-shield-alt fa-fw"></i> ' . __('Event Block Rules'),
                            'url' => $baseurl . '/servers/eventBlockRule',
                            'requirement' => $isSiteAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-ban fa-fw"></i> ' . __('Event Blocklists'),
                            'url' => $baseurl . '/eventBlocklists',
                            'requirement' => Configure::read('MISP.enableEventBlocklisting') !== false && $isSiteAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-building-slash fa-fw"></i> ' . __('Org Blocklists'),
                            'url' => $baseurl . '/orgBlocklists',
                            'requirement' => Configure::read('MISP.enableOrgBlocklisting') !== false && $isSiteAdmin
                        ),
                    )
                ),
                // Correlations Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-project-diagram fa-fw"></i> ' . __('Correlations'),
                    'children' => array(
                        [
                            'html' => '<i class="fas fa-chart-bar fa-fw"></i> ' . __('Top Correlations'),
                            'url' => $baseurl . '/correlations/top',
                            'requirement' => $isSiteAdmin
                        ],
                        [
                            'html' => '<i class="fas fa-ruler fa-fw"></i> ' . __('Correlation rules'),
                            'url' => $baseurl . '/correlationRules/index',
                            'requirement' => $isSiteAdmin
                        ],
                        [
                            'html' => sprintf(
                                '<span style="display: flex;"><i class="fas fa-exclamation-circle fa-fw"></i>&nbsp;<span>%s</span></span>',
                                __('Over-correlating values')
                            ),
                            'url' => $baseurl . '/correlations/overCorrelations',
                            'requirement' => $isSiteAdmin
                        ]
                    )
                ),
                // Settings Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-sliders-h fa-fw"></i> ' . __('Settings'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-sliders-h fa-fw"></i> ' . __('List User Settings'),
                            'url' => $baseurl . '/user_settings/index/user_id:all',
                            'requirement' => $isAdmin
                        ),
                        array(
                            'html' => '<i class="fas fa-cog fa-fw"></i> ' . __('Set User Setting'),
                            'url' => $baseurl . '/user_settings/setSetting',
                            'requirement' => $isAdmin
                        ),
                    )
                )
            )
        ),
        // 6. Audit
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-history fa-fw"></i> ',
            'text' => __('Logs'),
            'requirement' => $isAclAudit,
            'children' => array(
                array(
                    'html' => '<i class="fas fa-file-alt fa-fw"></i> ' . __('Application Logs'),
                    'url' => $baseurl . '/logs/index'
                ),
                array(
                    'html' => '<i class="fas fa-file-contract fa-fw"></i> ' . __('Audit Logs'),
                    'url' => $baseurl . '/admin/audit_logs/index',
                    'requirement' => Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index'),
                ),
                array(
                    'html' => '<i class="fas fa-file-signature fa-fw"></i> ' . __('Access Logs'),
                    'url' => $baseurl . '/admin/access_logs/index',
                    'requirement' => $isSiteAdmin
                ),
                array(
                    'html' => '<i class="fas fa-search fa-fw"></i> ' . __('Search Logs'),
                    'url' => $baseurl . '/logs/search',
                    'requirement' => $this->Acl->canAccess('logs', 'search')
                )
            )
        ),
        // 7. Automation
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-robot fa-fw"></i> ',
            'text' => __('Automation'),
            'children' => array(
                array(
                    'html' => '<i class="fas fa-book fa-fw"></i> ' . __('OpenAPI'),
                    'url' => $baseurl . '/api/openapi'
                ),
                array(
                    'html' => '<i class="fas fa-terminal fa-fw"></i> ' . __('REST client'),
                    'url' => $baseurl . '/api/rest',
                    'requirement' => $this->Acl->canAccess('api', 'rest')
                ),
                array(
                    'html' => '<i class="fas fa-file-export fa-fw"></i> ' . __('Export'),
                    'url' => $baseurl . '/events/export'
                ),
                array(
                    'html' => '<i class="fas fa-robot fa-fw"></i> ' . __('Automation'),
                    'url' => $baseurl . '/events/automation',
                    'requirement' => $this->Acl->canAccess('events', 'automation'),
                ),
            )
        ),
        // 8. Resources
        array(
            'type' => 'root',
            'html' => '<i class="fas fa-info-circle fa-fw"></i> ',
            'text' => __('Resources'),
            'children' => array(
                array(
                    'html' => '<i class="fas fa-newspaper fa-fw"></i> ' . __('News'),
                    'url' => $baseurl . '/news'
                ),
                array(
                    'type' => 'separator',
                    'requirement' => $this->Acl->canAccess('threads', 'index'),
                ),
                // Discussions Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-comments fa-fw"></i> ' . __('Discussions'),
                    'requirement' => $this->Acl->canAccess('threads', 'index'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-comments fa-fw"></i> ' . __('List Discussions'),
                            'url' => $baseurl . '/threads/index',
                            'requirement' => $this->Acl->canAccess('threads', 'index'),
                        ),
                        array(
                            'html' => '<i class="fas fa-comment-medical fa-fw"></i> ' . __('Start Discussion'),
                            'url' => $baseurl . '/posts/add',
                            'requirement' => $this->Acl->canAccess('posts', 'add'),
                        ),
                    )
                ),
                array(
                    'type' => 'separator'
                ),
                // Documentation Group
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-book fa-fw"></i> ' . __('Documentation'),
                    'children' => array(
                        array(
                            'html' => '<i class="fas fa-book-open fa-fw"></i> ' . __('User Guide'),
                            'url' => 'https://www.circl.lu/doc/misp/'
                        ),
                        array(
                            'html' => '<i class="fas fa-list-ul fa-fw"></i> ' . __('Categories & Types'),
                            'url' => $baseurl . '/pages/display/doc/categories_and_types'
                        ),
                        array(
                            'html' => '<i class="fas fa-gavel fa-fw"></i> ' . __('Terms & Conditions'),
                            'url' => $baseurl . '/users/terms'
                        ),

                    )
                ),
                array(
                    'type' => 'group',
                    'html' => '<i class="fas fa-palette fa-fw"></i> ' . __('Themes'),
                    'children' => (function() use ($theme, $themes, $themesEnabled, $baseurl) {
                        $children = [];
                        if (!$themesEnabled) {
                            $children[] = [
                                'html' => sprintf(
                                    '<div style="padding: 10px 15px; width: 400px; line-height: 1.4; border-bottom: 1px solid #444; margin-bottom: 5px;">' .
                                    '<span class="text-warning" style="font-weight: bold;"><i class="fas fa-exclamation-triangle"></i> %s</span><br>' .
                                    '<small style="opacity: 0.8;">%s</small>' .
                                    '</div>',
                                    __('Themes are not yet enabled.'),
                                    __('Contact your MISP administrator to set MISP.enable_themes to 1.')
                                ),
                                'url' => '#'
                            ];
                        }
                        $themeItems = array_map(function($tObj) use ($theme, $themesEnabled) {
                            $html = sprintf(
                                '<span id="%sToggle" class="setTheme style-inline-theme" style="cursor: pointer; display: block; padding: 10px 15px; min-width: 400px; %s" data-theme="%s">',
                                strtolower($tObj->name),
                                !$themesEnabled ? 'opacity: 0.5; pointer-events: none;' : '',
                                h($tObj->name)
                            );
                            $html .= sprintf(
                                '<div style="display: flex; justify-content: space-between; align-items: center;">' .
                                '<span style="font-weight: bold;"><i class="fas fa-desktop fa-fw"></i> %s%s</span>' .
                                '<span class="label %s">%s</span>' .
                                '</div>',
                                $tObj->hideFromUsers ? '<span class="text-error">[DEV]</span> ' : '',
                                h($tObj->label),
                                $theme === $tObj->name ? 'label-success' : 'label-default',
                                $theme === $tObj->name ? __('ON') : __('OFF')
                            );
                            if (!empty($tObj->description)) {
                                $html .= sprintf(
                                    '<div style="font-size: 0.9em; opacity: 0.6; margin-top: 4px; line-height: 1.2; white-space: normal; max-width: 450px; padding-left: 28px;">%s</div>',
                                    h($tObj->description)
                                );
                            }
                            $html .= '</span>';
                            return array(
                                'html' => $html,
                                'url' => '#'
                            );
                        }, $themes);
                        return array_merge($children, $themeItems);
                    })()
                )
            )
        )
    );

    $logo = '<span class="logoBlueStatic bold" id="smallLogo">MISP</span>';
    $today = date('md');
    if ($today >= 1222 && $today <= 1226) {
        $logo = '<span class="logoBlueStatic bold" id="smallLogo" title="' . __('Happy holidays!') .'">M🎄SP</span>';
    } else if ($today == 1231 || $today == 0101) {
        $logo = '<span class="logoBlueStatic bold" id="smallLogo" title="' . __('Happy New Year!') .'">🎉 MISP 🎉</span>';
    }
    $menu_right = array(
        array(
            'type' => 'root',
            'html' => sprintf('%s <i class="fas fa-caret-down"></i>', __('Bookmarks')),
            'children' => $topbarBookmarks,
        ),
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
            'html' => $logo
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
            ),
            'children' => array(
                array(
                    'html' => '<i class="fas fa-user fa-fw"></i> ' . __('My Profile'),
                    'url' => $baseurl . '/users/view/me'
                ),
                array(
                    'html' => '<i class="fas fa-cog fa-fw"></i> ' . __('My Settings'),
                    'url' => $baseurl . '/user_settings/index/user_id:me'
                ),
                array(
                    'html' => '<i class="fas fa-sliders-h fa-fw"></i> ' . __('Set Setting'),
                    'url' => $baseurl . '/user_settings/setSetting'
                ),
                array(
                    'html' => '<i class="fas fa-sign-out-alt fa-fw"></i> ' . __('Log out'),
                    'url' => $baseurl . '/users/logout',
                    'requirement' => empty(Configure::read('Plugin.CustomAuth_disable_logout'))
                )
            )
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
</div>
<script>
$(document).ready(function() {
    $('.setTheme').on('click', function(e) {
        e.preventDefault();
        e.stopPropagation();

        var theme = String($(this).data('theme') || '');
        var safeTheme = encodeURIComponent(theme);

        $.ajax({
            type: 'POST',
            url: '<?php echo $baseurl; ?>/user_settings/setTheme/' + safeTheme,
            success: function(data) {
                location.reload();
            },
            error: function(xhr, status, error) {
                alert('<?php echo __('Failed to toggle Beta UI. Please try again.'); ?>');
            }
        });
    });
});
</script>
