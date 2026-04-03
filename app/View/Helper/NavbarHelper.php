<?php
App::uses('AppHelper', 'View/Helper');
App::uses('Router', 'Routing');

class NavbarHelper extends AppHelper {

    public $helpers = ['Acl', 'UserName', 'Html', 'OrgImg'];


    public function build(array $context = [])
    {
        $me = $context['me'] ?? null;
        if (empty($me)) {
            return ['left' => [], 'right' => []];
        }

        $baseurl = $context['baseurl'] ?? Router::url('/', true);
        $currentController = strtolower($this->request->params['controller']);
        $currentAction = strtolower($this->request->params['action']);

        // --- LEFT ---
        $left = [];
        $left[] = $this->buildEventsMenu($context, $baseurl);
        $left[] = $this->buildDataMenu($context, $baseurl);
        $left[] = $this->buildSyncMenu($context, $baseurl);
        $left[] = $this->buildAdminMenu($context, $baseurl);
        $left[] = $this->buildLogsMenu($context, $baseurl);
        $left[] = $this->buildAutomationMenu($context, $baseurl);
        $left[] = $this->buildResourcesMenu($context, $baseurl);

        // --- RIGHT ---
        $right = [];
        $right[] = $this->buildBookmarksMenu($context, $baseurl);
        $right[] = $this->buildAccountMenu($context, $baseurl);

        // Filtering of inaccessible options
        $left = $this->filterMenu($left);
        $right = $this->filterMenu($right);

        // Highlight the menu of the current page
        $left = $this->markActive($left, $currentController);
        $right = $this->markActive($right, $currentController);

        return compact('left', 'right');
    }



    private function buildEventsMenu(array $context, $baseurl)
    {
        $eventsChildren = [
            [
                'type' => 'group',
                'label' => __('Events'),
                'icon' => 'fas fa-clipboard-list',
                'children' => [
                    [
                        'label' => __('Add'),
                        'url' => $baseurl . '/events/add',
                        'controller' => 'events',
                        'action' => 'add',
                        'requirement' => $this->Acl->canAccess('events', 'add'),
                        'icon' => 'fas fa-plus'
                    ],
                    [
                        'label' => __('Index'),
                        'url' => $baseurl . '/events/index',
                        'controller' => 'events',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ],
                ]
            ],
            // To implement later, when the object view will be ready
            /* [
                'type' => 'group',
                'label' => __('Objects'),
                'icon' => 'fas fa-cubes',
                'children' => [
                    [
                        'label' => __('Search'),
                        'url' => $baseurl . '/objects/search',
                        'controller' => 'objects',
                        'action' => 'seatch',
                        'icon' => 'fas fa-search'
                    ],
                    [
                        'label' => __('Index'),
                        'url' => $baseurl . '/objects/index',
                        'controller' => 'objects',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ]
                ]
            ], */
            [
                'type' => 'group',
                'label' => __('Attributes'),
                'icon' => 'fas fa-inbox',
                'children' => [
                    [
                        'label' => __('Search'),
                        'url' => $baseurl . '/attributes/search',
                        'controller' => 'attributes',
                        'action' => 'search',
                        'icon' => 'fas fa-search'
                    ],
                    [
                        'label' => __('Index'),
                        'url' => $baseurl . '/attributes/index',
                        'controller' => 'attributes',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Collections'),
                'url' => $baseurl . '/collections/index',
                'controller' => 'collections',
                'action' => 'index',
                'icon' => 'fas fa-folder',
            ],
            [
                'type' => 'group',
                'label' => __('Event Reports'),
                'url' => $baseurl . '/event_reports/index',
                'controller' => 'event_reports',
                'action' => 'index',
                'icon' => 'fas fa-file-alt',
            ],
            [
                'type' => 'group',
                'label' => __('Analyst Data'),
                'url' => $baseurl . '/analystData/index',
                'controller' => 'analystData',
                'action' => 'index',
                'icon' => 'fas fa-chart-bar',
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Proposals'),
                'icon' => 'fas fa-comment-dots',
                'children' => [
                    [
                        'label' => __('View'),
                        'url' => $baseurl . '/shadow_attributes/index',
                        'controller' => 'shadow_attributes',
                        'action' => 'index',
                        'icon' => 'fas fa-eye'
                    ],
                    [
                        'label' => __('Events with Proposals'),
                        'url' => $baseurl . '/shadow_attributes/search',
                        'controller' => 'shadow_attributes',
                        'action' => 'search',
                        'icon' => 'fas fa-clipboard-question'
                    ],
                    [
                        'label' => __('Delegation Requests'),
                        'url' => $baseurl . '/event_delegations/index',
                        'controller' => 'event_delegations',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('event_delegations', 'index'),
                        'icon' => 'fas fa-handshake'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Dashboard'),
                'url' => $baseurl . '/dashboards',
                'controller' => 'dashboards',
                'action' => '',
                'icon' => 'fas fa-chalkboard-user',
            ],
            [
                'type' => 'group',
                'label' => __('Statistics'),
                'url' => $baseurl . '/users/statistics',
                'controller' => 'users',
                'action' => 'statistics',
                'icon' => 'fas fa-pie-chart',
            ]
        ];

        return [
            'type' => 'root',
            'label' => __('Data points'),
            'icon' => 'fas fa-clipboard-list',
            'children' => $eventsChildren
        ];
    }

    private function buildDataMenu(array $context, $baseurl)
    {
        extract($context);
        $dataChildren = [
            [
                'type' => 'group',
                'label' => __('Tags & Taxonomies'),
                'icon' => 'fas fa-tags',
                'children' => [
                    [
                        'label' => __('Add Tag'),
                        'url' => $baseurl . '/tags/add',
                        'controller' => 'tags',
                        'action' => 'add',
                        'requirement' => $this->Acl->canAccess('tags', 'add'),
                        'icon' => 'fas fa-plus'
                    ],
                    [
                        'label' => __('List Tags'),
                        'url' => $baseurl . '/tags/index',
                        'controller' => 'tags',
                        'action' => 'index',
                        'icon' => 'fas fa-tag'
                    ],
                    [
                        'label' => __('List Tag Collections'),
                        'url' => $baseurl . '/tagCollections/index',
                        'controller' => 'tagCollections',
                        'action' => 'index',
                        'icon' => 'fas fa-tags'
                    ],
                    [
                        'label' => __('List Taxonomies'),
                        'url' => $baseurl . '/taxonomies/index',
                        'controller' => 'taxonomies',
                        'action' => 'index',
                        'icon' => 'fas fa-sitemap'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Galaxies'),
                'icon' => 'fab fa-galactic-republic',
                'children' => [
                    [
                        'label' => __('List Galaxies'),
                        'url' => $baseurl . '/galaxies/index',
                        'controller' => 'galaxies',
                        'action' => 'index',
                        'icon' => 'fab fa-galactic-republic'
                    ],
                    [
                        'label' => __('List Galaxy Relationships'),
                        'url' => $baseurl . '/galaxy_cluster_relations/index',
                        'controller' => 'galaxy_cluster_relations',
                        'action' => 'index',
                        'icon' => 'fas fa-project-diagram'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Decaying Models'),
                'icon' => 'fas fa-hourglass-half',
                'children' => [
                    [
                        'label' => __('Decaying Models Tools'),
                        'url' => $baseurl . '/decayingModel/decayingTool',
                        'controller' => 'decayingModel',
                        'action' => 'decayingTool',
                        'icon' => 'fas fa-toolbox'
                    ],
                    [
                        'label' => __('List Decaying Models'),
                        'url' => $baseurl . '/decayingModel/index',
                        'controller' => 'decayingModel',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Templates'),
                'icon' => 'fas fa-file-code',
                'children' => [
                    [
                        'label' => __('List Templates'),
                        'url' => $baseurl . '/templates/index',
                        'controller' => 'templates',
                        'action' => 'index',
                        'icon' => 'fas fa-file-code'
                    ],
                    [
                        'label' => __('List Object Templates'),
                        'url' => $baseurl . '/objectTemplates/index',
                        'controller' => 'objectTemplates',
                        'action' => 'templex',
                        'icon' => 'fas fa-cubes'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Filters & Lists'),
                'icon' => 'fas fa-list-alt',
                'children' => [
                    [
                        'label' => __('Warninglists'),
                        'url' => $baseurl . '/warninglists/index',
                        'controller' => 'warninglists',
                        'action' => 'index',
                        'icon' => 'fas fa-exclamation-triangle'
                    ],
                    [
                        'label' => __('Noticelists'),
                        'url' => $baseurl . '/noticelists/index',
                        'controller' => 'noticelists',
                        'action' => 'index',
                        'icon' => 'fas fa-info-circle'
                    ],
                    [
                        'label' => __('Import Regexp'),
                        'url' => $baseurl . '/admin/regexp/index',
                        'controller' => 'regexp',
                        'action' => 'index',
                        'requirement' => $isAclRegexp,
                        'icon' => 'fas fa-code'
                    ],
                    [
                        'label' => __('Import Regexp'),
                        'url' => $baseurl . '/regexp/index',
                        'controller' => 'regexp',
                        'action' => 'index',
                        'requirement' => !$isAclRegexp,
                        'icon' => 'fas fa-code'
                    ],
                    [
                        'label' => __('Signature Allowedlist'),
                        'url' => $baseurl . '/admin/allowedlists/index',
                        'controller' => 'allowedlists',
                        'action' => 'index',
                        'requirement' => $isAclRegexp,
                        'icon' => 'fas fa-check-circle'
                    ],
                    [
                        'label' => __('Signature Allowedlist'),
                        'url' => $baseurl . '/allowedlists/index',
                        'controller' => 'allowedlists',
                        'action' => 'index',
                        'requirement' => !$isAclRegexp,
                        'icon' => 'fas fa-check-circle'
                    ],
                    [
                        'label' => __('Correlation Exclusions'),
                        'url' => $baseurl . '/correlation_exclusions/index',
                        'controller' => 'correlation_exclusions',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('correlation_exclusions', 'index'),
                        'icon' => 'fas fa-filter'
                    ]
                ]
            ]
        ];

        return [
            'type' => 'root',
            'label' => __('Data models'),
            'icon' => 'fas fa-database',
            'children' => $dataChildren
        ];
    }


    private function buildSyncMenu(array $context, $baseurl)
    {
        extract($context);

        $syncChildren = [
            [
                'type' => 'group',
                'label' => __('Servers & Feeds'),
                'icon' => 'fas fa-server',
                'children' => [
                    [
                        'label' => __('Create Sync Config'),
                        'url' => $baseurl . '/syncConfigs/add',
                        'controller' => 'syncConfigs',
                        'action' => 'add',
                        'requirement' => $isAclSync && !$isSiteAdmin,
                        'icon' => 'fas fa-rotate'
                    ],
                    [
                        'label' => __('Remote Servers'),
                        'url' => $baseurl . '/servers/index',
                        'controller' => 'servers',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('servers', 'index'),
                        'icon' => 'fas fa-server'
                    ],
                    [
                        'label' => __('Feeds'),
                        'url' => $baseurl . '/feeds/index',
                        'controller' => 'feeds',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('feeds', 'index'),
                        'icon' => 'fas fa-rss'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Sharing Groups'),
                'icon' => 'fas fa-users-rays',
                'children' => [
                    [
                        'label' => __('Add Sharing Group'),
                        'url' => $baseurl . '/sharingGroups/add',
                        'controller' => 'sharingGroups',
                        'action' => 'add',
                        'requirement' => $this->Acl->canAccess('sharing_groups', 'add'),
                        'icon' => 'fas fa-plus'
                    ],
                    [
                        'label' => __('List Sharing Groups'),
                        'url' => $baseurl . '/sharingGroups/index',
                        'controller' => 'sharingGroups',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ],
                    [
                        'label' => __('Add Sharing Group Blueprint'),
                        'url' => $baseurl . '/sharingGroupBlueprints/add',
                        'controller' => 'sharingGroupBlueprints',
                        'action' => 'add',
                        'requirement' => $this->Acl->canAccess('sharing_group_blueprints', 'index'),
                        'icon' => 'fas fa-plus'
                    ],
                    [
                        'label' => __('List Sharing Group Blueprints'),
                        'url' => $baseurl . '/sharingGroupBlueprints/index',
                        'controller' => 'sharingGroupBlueprints',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('sharing_group_blueprints', 'add'),
                        'icon' => 'fas fa-drafting-compass'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Integrations'),
                'icon' => 'fas fa-plug',
                'children' => [
                    [
                        'label' => __('Comunities'),
                        'url' => $baseurl . '/communities/index',
                        'controller' => 'communities',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('communities', 'index'),
                        'icon' => 'fas fa-users'
                    ],
                    [
                        'label' => __('Cerebrates'),
                        'url' => $baseurl . '/cerebrates/index',
                        'controller' => 'cerebrates',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('cerebrates', 'index'),
                        'icon' => 'fas fa-network-wired'
                    ],
                    [
                        'label' => __('TAXII Servers'),
                        'url' => $baseurl . '/TaxiiServers/index',
                        'controller' => 'TaxiiServers',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('taxiiServers', 'index'),
                        'icon' => 'fas fa-cloud'
                    ],
                    [
                        'label' => __('Sighting DB'),
                        'url' => $baseurl . '/sightingdb/index',
                        'controller' => 'sightingdb',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('sightingdb', 'index'),
                        'icon' => 'fas fa-eye'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Event ID Translator'),
                'url' => $baseurl . '/servers/idTranslator',
                'controller' => 'servers',
                'action' => 'idTranslator',
                'icon' => 'fas fa-exchange-alt',
            ]
        ];

        return [
            'type' => 'root',
            'label' => __('Sync'),
            'requirement' =>  $isAclSync || $isAdmin || $hostOrgUser,
            'icon' => 'fas fa-rotate',
            'children' => $syncChildren
        ];
    }


    private function buildAdminMenu(array $context, $baseurl)
    {
        extract($context);

        $adminChildren = [
            [
                'type' => 'group',
                'label' => __('Server Settings & Maintenance'),
                'url' => $baseurl . '/servers/serverSettings',
                'controller' => 'servers',
                'action' => 'serverSettings',
                'icon' => 'fas fa-gears',
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Users & Orgs'),
                'icon' => 'fas fa-building-user',
                'children' => [
                    [
                        'label' => __('Add User'),
                        'url' => $baseurl . '/admin/users/add',
                        'controller' => 'users',
                        'action' => 'add',
                        'requirement' => $this->Acl->canAccess('users', 'admin_add'),
                        'icon' => 'fas fa-plus'
                    ],
                    [
                        'label' => __('List Users'),
                        'url' => $baseurl . '/admin/users/index',
                        'controller' => 'users',
                        'action' => 'index',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-users-between-lines'
                    ],
                    [
                        'label' => __('Contact User'),
                        'url' => $baseurl . '/admin/users/email',
                        'controller' => 'users',
                        'action' => 'email',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-envelope'
                    ],
                    [
                        'label' => __('List Organisations'),
                        'url' => $baseurl . '/organisations/index',
                        'controller' => 'organisations',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('organisations', 'index'),
                        'icon' => 'fas fa-building'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Roles & Permissions'),
                'icon' => 'fas fa-user-tag',
                'children' => [
                    [
                        'label' => __('List Roles'),
                        'url' => $baseurl . '/roles/index',
                        'controller' => 'roles',
                        'action' => 'index',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-users-line'
                    ],
                    [
                        'label' => __('List Auth Keys'),
                        'url' => $baseurl . '/auth_keys/index',
                        'controller' => 'auth_keys',
                        'action' => 'index',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-key'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('System jobs'),
                'icon' => 'fas fa-helmet-safety',
                'children' => [
                    [
                        'label' => __('Workflow'),
                        'url' => $baseurl . '/workflows/triggers',
                        'controller' => 'workflows',
                        'action' => 'triggers',
                        'requirement' => $isSiteAdmin,
                        'icon' => 'fas fa-project-diagram'
                    ],
                    [
                        'label' => __('Jobs'),
                        'url' => $baseurl . '/jobs/index',
                        'controller' => 'jobs',
                        'action' => 'index',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin,
                        'icon' => 'fas fa-tasks'
                    ],
                    [
                        'label' => __('Scheduled Tasks'),
                        'url' => $baseurl . '/tasks',
                        'controller' => 'tasks',
                        'action' => '',
                        'requirement' => Configure::read('MISP.background_jobs') && $isSiteAdmin,
                        'icon' => 'fas fa-clock'
                    ],
                    [
                        'label' => __('Benchmarking'),
                        'url' => $baseurl . '/benchmarks/index',
                        'controller' => 'benchmarks',
                        'action' => 'index',
                        'requirement' => $isSiteAdmin && Configure::read('Plugin.Benchmarking_enable'),
                        'icon' => 'fas fa-gauge'
                    ],
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Blocklisting'),
                'icon' => 'fas fa-ban',
                'children' => [
                    [
                        'label' => __('Blocklist Event'),
                        'url' => $baseurl . '/eventBlocklists',
                        'controller' => 'eventBlocklists',
                        'action' => '',
                        'requirement' => Configure::read('MISP.enableEventBlocklisting') !== false && $isSiteAdmin,
                        'icon' => 'fas fa-file-circle-exclamation'
                    ],
                    [
                        'label' => __('Blocklists Organisations'),
                        'url' => $baseurl . '/orgBlocklists',
                        'controller' => 'orgBlocklists',
                        'action' => '',
                        'requirement' => Configure::read('MISP.enableOrgBlocklisting') !== false && $isSiteAdmin,
                        'icon' => 'fas fa-building-circle-exclamation'
                    ],
                    [
                        'label' => __('Blocklists Sightings'),
                        'url' => $baseurl . '/sightingBlocklists',
                        'controller' => 'sightingBlocklists',
                        'action' => '',
                        'requirement' => Configure::read('MISP.enableSightingBlocklisting') !== false && $isSiteAdmin,
                        'icon' => 'fas fa-heart-circle-exclamation'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Correlations'),
                'icon' => 'fas fa-circle-nodes',
                'children' => [
                    [
                        'label' => __('Top correlations'),
                        'url' => $baseurl . '/workflows/triggers',
                        'controller' => 'workflows',
                        'action' => 'triggers',
                        'requirement' => $isSiteAdmin,
                        'icon' => 'fas fa-ranking-star'
                    ],
                    [
                        'label' => __('Correlations rules'),
                        'url' => $baseurl . '/correlationRules/index',
                        'controller' => 'correlationRules',
                        'action' => 'index',
                        'requirement' => $isSiteAdmin,
                        'icon' => 'fas fa-comment-nodes'
                    ],
                    [
                        'label' => __('Over-correlating values'),
                        'url' => $baseurl . '/correlations/overCorrelations',
                        'controller' => 'correlations',
                        'action' => 'overCorrelations',
                        'requirement' => $isSiteAdmin,
                        'icon' => 'fas fa-hexagon-nodes-bolt'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Settings'),
                'icon' => 'fas fa-sliders',
                'children' => [
                    [
                        'label' => __('Set User Settings'),
                        'url' => $baseurl . '/user_settings/setSetting',
                        'controller' => 'user_settings',
                        'action' => 'setSetting',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-gear'
                    ],
                    [
                        'label' => __('List User Settings'),
                        'url' => $baseurl . '/user_settings/index',
                        'controller' => 'user_settings',
                        'action' => 'index',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-users-gear'
                    ]
                ]
            ]
        ];
        return [
            'type' => 'root',
            'label' => __('Administration'),
            'icon' => 'fas fa-tools',
            'requirement' => $isAdmin,
            'children' => $adminChildren
        ];
    }


    private function buildLogsMenu(array $context, $baseurl)
    {
        extract($context);

        $logChildren = [
            [
                'type' => 'group',
                'label' => __('Application logs'),
                'url' => $baseurl . '/logs/index',
                'controller' => 'logs',
                'action' => 'index',
                'icon' => 'fas fa-file-alt',
            ],
            ['divider' => true, 'requirement' => Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index')],
            [
                'type' => 'group',
                'label' => __('Audit logs'),
                'url' => $baseurl . '/admin/audit_logs/index',
                'controller' => 'audit_logs',
                'action' => 'index',
                'requirement' => Configure::read('MISP.log_new_audit') && $this->Acl->canAccess('auditLogs', 'admin_index'),
                'icon' => 'fas fa-file-contract',
            ],
            ['divider' => true, 'requirement' => $isSiteAdmin],
            [
                'type' => 'group',
                'label' => __('Access logs'),
                'url' => $baseurl . '/admin/access_logs/index',
                'controller' => 'access_logs',
                'action' => 'index',
                'requirement' => $isSiteAdmin,
                'icon' => 'fas fa-file-pen',
            ],
            ['divider' => true, 'requirement' => $this->Acl->canAccess('logs', 'search')],
            [
                'type' => 'group',
                'label' => __('Search logs'),
                'url' => $baseurl . '/logs/search',
                'controller' => 'logs',
                'action' => 'index',
                'requirement' => $this->Acl->canAccess('logs', 'search'),
                'icon' => 'fas fa-search',
            ]
        ];
        return [
                'type' => 'root',
                'label' => __('Logs'),
                'requirement' => $isAclAudit,
                'icon' => 'fas fa-history',
                'children' => $logChildren
        ];
    }

    private function buildAutomationMenu(array $context, $baseurl)
    {
        extract($context);

        $automationChildren = [
            [
                'type' => 'group',
                'label' => __('Open API'),
                'url' => $baseurl . '/api/openapi',
                'controller' => 'api',
                'action' => 'openapi',
                'icon' => 'fas fa-book-open',
            ],
            [
                'type' => 'group',
                'label' => __('REST Client'),
                'url' => $baseurl . '/api/rest',
                'controller' => 'api',
                'action' => 'rest',
                'requirement' => $this->Acl->canAccess('api', 'rest'),
                'icon' => 'fas fa-terminal',
            ],
            ['divider' => true, 'requirement' => $this->Acl->canAccess('events', 'automation')],
            [
                'type' => 'group',
                'label' => __('Automation'),
                'url' => $baseurl . '/events/automation',
                'controller' => 'events',
                'action' => 'automation',
                'requirement' => $this->Acl->canAccess('events', 'automation'),
                'icon' => 'fas fa-robot',
            ],
            [
                'type' => 'group',
                'label' => __('Export'),
                'url' => $baseurl . '/events/export',
                'controller' => 'events',
                'action' => 'export',
                'icon' => 'fas fa-file-export',
            ]
        ];

        return [
                'type' => 'root',
                'label' => __('API'),
                'icon' => 'fas fa-code',
                'children' => $automationChildren
        ];
    }

    private function buildResourcesMenu(array $context, $baseurl)
    {
        extract($context);

        $resourcesChildren = [
            [
                'type' => 'group',
                'label' => __('News'),
                'url' => $baseurl . '/news',
                'controller' => 'news',
                'action' => '',
                'icon' => 'fas fa-newspaper',
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Documentation'),
                'icon' => 'fas fa-book',
                'children' => [
                    [
                        'label' => __('User Guide'),
                        'url' => 'https://www.circl.lu/doc/misp/',
                        'icon' => 'fas fa-address-book'
                    ],
                    [
                        'label' => __('Categories & Types'),
                        'url' => $baseurl . '/pages/display/doc/categories_and_types',
                        'controller' => 'doc',
                        'action' => 'categories_and_types',
                        'icon' => 'fas fa-table-list'
                    ],
                    [
                        'label' => __('Terms & Conditions'),
                        'url' => $baseurl . '/users/terms',
                        'controller' => 'users',
                        'action' => 'terms',
                        'icon' => 'fas fa-gavel'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Themes'),
                'icon' => 'fas fa-palette',
                'children' => $this->buildThemesMenu($context)
            ]
        ];
        return [
                'type' => 'root',
                'label' => __('Resources'),
                'icon' => 'fas fa-circle-info',
                'children' => $resourcesChildren
        ];
    }

    private function buildThemesMenu(array $context)
    {
        extract($context);

        $themes = $context['themes'] ?? [];
        $theme = $context['theme'] ?? null;
        $themesEnabled = $context['themesEnabled'] ?? false;

        $items = [];

        if (!$themesEnabled) {
            $items[] = [
                'type' => 'message',
                'label' => __('Themes are not yet enabled.'),
                'description' => __('Contact your MISP administrator to set MISP.enable_themes to 1.')
            ];
        }

        foreach ($themes as $tObj) {

            $items[] = [
                'type' => 'theme',
                'label' => $tObj->label,
                'theme' => $tObj->name,
                'description' => $tObj->description ?? '',
                'on' => $theme === $tObj->name
            ];
        }

        return $items;
    }

    private function buildBookmarksMenu(array $context, $baseurl)
    {
        extract($context);

        $bookmarksChildren = [];
        if (!empty($bookmarks)) {
            foreach ($bookmarks as $b) {
            $bookmarksChildren[] = [
                'label' => $b['Bookmark']['name'],
                'url' => h($b['Bookmark']['url'])
            ];
            }

            $bookmarksChildren[] = ['divider' => true];
        }

        //TO DO
        $bookmarksChildren[] = [
            'label' => __('Set this page as homepage'),
            'url' => '',
            'icon' => 'fas fa-home'
        ];

        $bookmarksChildren[] = [
            'label' => __('Add Bookmark'),
            'url' => $baseurl . '/bookmarks/add',
            'controller' => 'bookmarks',
            'action' => 'add',
            'icon' => 'fas fa-plus'
        ];
        $bookmarksChildren[] = [
            'label' => __('Manage Bookmarks'),
            'url' => $baseurl . '/bookmarks/index',
            'controller' => 'bookmarks',
            'action' => 'index',
            'icon' => 'fas fa-cog'
        ];

        return [
            'type' => 'root',
            'label' => __('Bookmarks'),
            'icon' => 'fas fa-star',
            'children' => $bookmarksChildren
        ];
    }


    private function buildAccountMenu(array $context, $baseurl)
    {
        extract($context);

        $profileChildren = [
            [
                'label' => __('My Profile'),
                'url' => $baseurl . '/users/view/me',
                'controller' => 'users',
                'action' => 'view',
                'icon' => 'fas fa-user'
            ],
            [
                'label' => __('Log out'),
                'url' => $baseurl . '/users/logout',
                'controller' => 'users',
                'action' => 'logout',
                'icon' => 'fas fa-right-from-bracket'
            ]
        ];

        $orgLogo = $this->OrgImg->getOrgLogoV2($me, 20);

        // Remove the <a> wrapper of the logo
        $orgLogo = preg_replace('/<a[^>]*>(.*?)<\/a>/i', '$1', $orgLogo);

        return [
            'type' => 'root',
            'label' => h($this->UserName->convertEmailToName($me['email'])),
            'image' => $orgLogo,
            'children' => $profileChildren
        ];

    }


    /**
     * Recursively filter menu items based on requirement and children visibility
     */
    private function filterMenu(array $items)
    {
        $filtered = [];

        foreach ($items as $item) {

            // Check requirement on the item itself
            if (isset($item['requirement']) && !$item['requirement']) {
                continue;
            }

            // Handle children recursively
            if (!empty($item['children'])) {
                $item['children'] = $this->filterMenu($item['children']);

                // Remove item if no visible children left
                if (empty($item['children'])) {
                    continue;
                }
            }

            $filtered[] = $item;
        }

        // Clean useless dividers
        $filtered = $this->cleanDividers($filtered);

        return $filtered;
    }


    /**
     * Remove useless dividers (start, end, duplicate)
     */
    private function cleanDividers(array $items)
    {
        $result = [];
        $previousWasDivider = false;

        foreach ($items as $item) {

            if (!empty($item['divider'])) {

                // Skip divider at start or duplicate
                if (empty($result) || $previousWasDivider) {
                    continue;
                }

                $previousWasDivider = true;
            } else {
                $previousWasDivider = false;
            }

            $result[] = $item;
        }

        // Remove divider at end
        if (!empty($result) && !empty(end($result)['divider'])) {
            array_pop($result);
        }

        return $result;
    }

    /**
    * Recursively mark active menu items (robust controller/action matching)
    */
    private function markActive(array $items, $currentController)
    {
        foreach ($items as &$item) {

            $item['active'] = false;

            // Direct match on controller
            if (!empty($item['controller'])) {
                if (strtolower($item['controller']) === strtolower($currentController)) {
                    $item['active'] = true;
                }
            }

            // Recursive children check
            if (!empty($item['children'])) {
                $item['children'] = $this->markActive(
                    $item['children'],
                    $currentController,
                );

                foreach ($item['children'] as $child) {
                    if (!empty($child['active'])) {
                        $item['active'] = true;
                        break;
                    }
                }
            }
        }

        return $items;
    }


}
