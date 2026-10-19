<?php
App::uses('AppHelper', 'View/Helper');
App::uses('Router', 'Routing');
App::uses('MispTheme', 'Lib/MispTheme');

class NavbarHelper extends AppHelper {

    public $helpers = ['Acl', 'UserName', 'Html', 'OrgImg'];

    // Maps controller (lowercased) → menu id.
    // Use a nested array to override by action: ['default' => id, 'action' => id].
    private const ACTIVE_MENU_MAP = [
        // Data points
        'events'            => ['default' => 'datapoints', 'automation' => 'api', 'export' => 'api'],
        'attributes'        => 'datapoints',
        'objects'           => 'datapoints',
        'values'            => 'datapoints',
        'shadow_attributes' => 'datapoints',
        'event_delegations' => 'datapoints',
        'collections'       => 'datapoints',
        'event_reports'     => 'datapoints',
        'eventreporttemplatevariables'     => 'datapoints',
        'analystdata'       => 'datapoints',
        'dashboards'        => 'datapoints',
        // Data models
        'tags'                     => 'datamodels',
        'tagcollections'           => 'datamodels',
        'taxonomies'               => 'datamodels',
        'galaxies'                 => 'datamodels',
        'galaxy_clusters'          => 'datamodels',
        'galaxy_cluster_relations' => 'datamodels',
        'decayingmodel'            => 'datamodels',
        'analystprofiles'          => 'datamodels',
        'objecttemplates'          => 'datamodels',
        'object_relationships'     => 'datamodels',
        'event_templates'          => 'datamodels',
        'warninglists'             => 'datamodels',
        'noticelists'              => 'datamodels',
        'regexp'                   => 'datamodels',
        'correlation_exclusions'   => 'datamodels',
        // Sync
        'feeds'                  => 'sync',
        'sharinggroups'          => 'sync',
        'sharinggroupblueprints' => 'sync',
        'communities'            => 'sync',
        'cerebrates'             => 'sync',
        'taxiiservers'           => 'sync',
        'sightingdb'             => 'sync',
        'servers'                => ['default' => 'sync', 'serversettings' => 'administration', 'eventblockrule' => 'administration'],
        // Administration
        'organisations'      => 'administration',
        'roles'              => 'administration',
        'auth_keys'          => 'administration',
        'workflows'          => 'administration',
        'workflowblueprints' => 'administration',
        'jobs'               => 'administration',
        'tasks'              => 'administration',
        'benchmarks'         => 'administration',
        'eventblocklists'    => 'administration',
        'orgblocklists'      => 'administration',
        'sightingblocklists' => 'administration',
        'correlationrules'   => 'administration',
        'correlations'       => 'administration',
        'user_settings'      => 'administration',
        'users'              => [
            'default'       => 'account',
            'admin_default' => 'administration', // any admin_* action (index, view, add, email, edit…)
            'statistics'    => 'datapoints',
            'terms'         => 'resources',
            'registrations' => 'administration',
        ],
        // Logs
        'logs'        => 'logs',
        'audit_logs'  => 'logs',
        'access_logs' => 'logs',
        // API
        'api' => 'api',
        // Resources
        'doc'   => 'resources',
        'pages' => 'resources',
        // Bookmarks
        'bookmarks' => 'bookmarks',
    ];


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
        $right[] = $this->buildIntelGraphItem($context);
        $right[] = $this->buildNewsItem($context);
        $right[] = empty($context['sidePanels']['bookmarks'])
            ? $this->buildBookmarksMenu($context, $baseurl)
            : $this->buildBookmarksItem($context);
        $right[] = $this->buildAccountMenu($context, $baseurl);

        // Filtering of inaccessible options
        $left = $this->filterMenu($left);
        $right = $this->filterMenu($right);

        // Highlight the menu of the current page
        $activeMenuId = $this->resolveActiveMenu($currentController, $currentAction);
        $left = $this->markActive($left, $activeMenuId);
        $right = $this->markActive($right, $activeMenuId);

        return compact('left', 'right');
    }



    private function buildEventsMenu(array $context, $baseurl)
    {
        $eventsChildren = [
            [
                'type' => 'group',
                'label' => __('Events'),
                'url' => $baseurl . '/events/index',
                'controller' => 'events',
                'action' => 'index',
                'icon' => 'misp-icon misp-icon-event misp-simple',
            ],
            [
                'type' => 'group',
                'label' => __('Objects'),
                'url' => $baseurl . '/objects/index',
                'controller' => 'objects',
                'action' => 'index',
                'icon' => 'fas fa-cubes',
            ],
            [
                'type' => 'group',
                'label' => __('Attributes'),
                'url' => $baseurl . '/attributes/index',
                'controller' => 'attributes',
                'action' => 'index',
                'icon' => 'misp-icon misp-icon-attribute misp-simple',
            ],
            [
                // The entry names the feature and points at the way in:
                // the profile's subject is a value the reader supplies,
                // so there is nothing to link but the resolver.
                'type' => 'group',
                'label' => __('Value Intelligence'),
                'url' => $baseurl . '/values/index',
                'controller' => 'values',
                'action' => 'index',
                'icon' => 'misp-icon misp-icon-value-intelligence misp-simple',
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
                'icon' => 'misp-icon misp-icon-report misp-simple',
                'children' => [
                    [
                        'label' => __('Index'),
                        'url' => $baseurl . '/event_reports/index',
                        'controller' => 'event_reports',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ],
                    [
                        'label' => __('Template Variables'),
                        'url' => $baseurl . '/EventReportTemplateVariables/index',
                        'controller' => 'EventReportTemplateVariables',
                        'action' => 'index',
                        'icon' => 'fas fa-scroll'
                    ]
                ]
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
                        'label' => __('Index'),
                        'url' => $baseurl . '/shadow_attributes/index',
                        'controller' => 'shadow_attributes',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ],
                    [
                        'label' => __('Events with Proposals'),
                        'url' => $baseurl . '/events/proposalEventIndex',
                        'controller' => 'events',
                        'action' => 'proposalEventIndex',
                        'icon' => 'misp-icon misp-icon-event misp-simple'
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
                'icon' => 'fas fa-chart-pie',
            ],
        ];

        return [
            'type' => 'root',
            'id'   => 'datapoints',
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
                'icon' => 'misp-icon misp-icon-tag misp-simple',
                'children' => [
                    [
                        'label' => __('List Taxonomies'),
                        'url' => $baseurl . '/taxonomies/index',
                        'controller' => 'taxonomies',
                        'action' => 'index',
                        'icon' => 'misp-icon misp-icon-taxonomy misp-simple'
                    ],
                    [
                        'label' => __('List Tags'),
                        'url' => $baseurl . '/tags/index',
                        'controller' => 'tags',
                        'action' => 'index',
                        'icon' => 'misp-icon misp-icon-tag misp-simple'
                    ],
                    [
                        'label' => __('List Tag Collections'),
                        'url' => $baseurl . '/tagCollections/index',
                        'controller' => 'tagCollections',
                        'action' => 'index',
                        'icon' => 'fas fa-tags'
                    ]
                ]
            ],
            [
                'type' => 'group',
                'label' => __('Galaxies'),
                'icon' => 'misp-icon misp-icon-galaxy misp-simple',
                'children' => [
                    [
                        'label' => __('List Galaxies'),
                        'url' => $baseurl . '/galaxies/index',
                        'controller' => 'galaxies',
                        'action' => 'index',
                        'icon' => 'misp-icon misp-icon-galaxy misp-simple'
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
                'url' => $baseurl . '/decayingModel/index',
                'controller' => 'decayingModel',
                'action' => 'index',
                'icon' => 'fas fa-hourglass-half',
                //'children' => [
                    // [
                    //     'label' => __('Index'),
                    //     'url' => $baseurl . '/decayingModel/index',
                    //     'controller' => 'decayingModel',
                    //     'action' => 'index',
                    //     'icon' => 'fas fa-list'
                    // ],
                    // [
                    //     'label' => __('Decaying Models Tool'),
                    //     'url' => $baseurl . '/decayingModel/decayingTool',
                    //     'controller' => 'decayingModel',
                    //     'action' => 'decayingTool',
                    //     'icon' => 'fas fa-toolbox'
                    // ]
                //]
            ],
            [
                'type' => 'group',
                'label' => __('Analyst Profiles'),
                'url' => $baseurl . '/analystProfiles/index',
                'controller' => 'analystProfiles',
                'action' => 'index',
                'icon' => 'fas fa-magnifying-glass-chart'
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Templates'),
                'icon' => 'fas fa-file-code',
                'children' => [
                    [
                        'label' => __('List Event Templates'),
                        'url' => $baseurl . '/event_templates/index',
                        'controller' => 'event_templates',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('eventTemplates', 'index'),
                        'icon' => 'misp-icon misp-icon-event misp-simple'
                    ],
                    [
                        'label' => __('List Object Templates'),
                        'url' => $baseurl . '/objectTemplates/index',
                        'controller' => 'objectTemplates',
                        'action' => 'index',
                        'icon' => 'misp-icon misp-icon-object misp-simple'
                    ],
                    [
                        'label' => __('List Object Relationships'),
                        'url' => $baseurl . '/object_relationships/index',
                        'controller' => 'object_relationships',
                        'action' => 'index',
                        'icon' => 'fas fa-cubes'
                    ],
                    // [
                    //     'label' => __('Add Event Template'),
                    //     'url' => $baseurl . '/event_templates/add',
                    //     'controller' => 'event_templates',
                    //     'action' => 'add',
                    //     'requirement' => $this->Acl->canAccess('eventTemplates', 'add'),
                    //     'icon' => 'fas fa-plus'
                    // ]
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
            'id'   => 'datamodels',
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
                'icon' => 'misp-icon misp-icon-sharing-group misp-simple',
                'children' => [
                    // [
                    //     'label' => __('Add Sharing Group'),
                    //     'url' => $baseurl . '/SharingGroups/add',
                    //     'controller' => 'SharingGroups',
                    //     'action' => 'add',
                    //     'requirement' => $this->Acl->canAccess('SharingGroups', 'add'),
                    //     'icon' => 'fas fa-plus'
                    // ],
                    [
                        'label' => __('List Sharing Groups'),
                        'url' => $baseurl . '/SharingGroups/index',
                        'controller' => 'SharingGroups',
                        'action' => 'index',
                        'icon' => 'fas fa-list'
                    ],
                    // [
                    //     'label' => __('Add Sharing Group Blueprint'),
                    //     'url' => $baseurl . '/SharingGroupBlueprints/add',
                    //     'controller' => 'SharingGroupBlueprints',
                    //     'action' => 'add',
                    //     'requirement' => $this->Acl->canAccess('SharingGroupBlueprints', 'index'),
                    //     'icon' => 'fas fa-plus'
                    // ],
                    [
                        'label' => __('List Sharing Group Blueprints'),
                        'url' => $baseurl . '/SharingGroupBlueprints/index',
                        'controller' => 'SharingGroupBlueprints',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('SharingGroupBlueprints', 'add'),
                        'icon' => 'fas fa-drafting-compass'
                    ]
                ]
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'id' => 'integrations',
                'label' => __('Integrations'),
                'icon' => 'fas fa-plug',
                'children' => [
                    [
                        'label' => __('Communities'),
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
                        'url' => $baseurl . '/taxiiServers/index',
                        'controller' => 'taxiiServers',
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
                        'icon' => 'misp-icon misp-icon-sighting misp-simple'
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
            'id'   => 'sync',
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
                'requirement' => $this->Acl->canAccess('servers', 'serverSettings'),
                'icon' => 'fas fa-gears',
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Users & Orgs'),
                'icon' => 'fas fa-building-user',
                'children' => [
                    // [
                    //     'label' => __('Add User'),
                    //     'url' => $baseurl . '/admin/users/add',
                    //     'controller' => 'users',
                    //     'action' => 'add',
                    //     'requirement' => $this->Acl->canAccess('users', 'admin_add'),
                    //     'icon' => 'fas fa-plus'
                    // ],
                    [
                        'label' => __('List Users'),
                        'url' => $baseurl . '/admin/users/index',
                        'controller' => 'users',
                        'action' => 'index',
                        'requirement' => $isAdmin,
                        'icon' => 'misp-icon misp-icon-user2 misp-simple'
                    ],
                    [
                        'label' => __('User Settings'),
                        'url' => $baseurl . '/user_settings/index',
                        'controller' => 'user_settings',
                        'action' => 'index',
                        'requirement' => $isAdmin,
                        'icon' => 'fas fa-sliders'
                    ],
                    [
                        'label' => __('List Organisations'),
                        'url' => $baseurl . '/organisations/index',
                        'controller' => 'organisations',
                        'action' => 'index',
                        'requirement' => $this->Acl->canAccess('organisations', 'index'),
                        'icon' => 'misp-icon misp-icon-organisation misp-simple'
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
                        'url' => $baseurl . '/workflows/index',
                        'controller' => 'workflows',
                        'action' => 'index',
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
                'id' => 'blocklisting',
                'label' => __('Blocklisting'),
                'icon' => 'fas fa-ban',
                'children' => [
                    [
                        'label' => __('Event Block Rules'),
                        'url' => $baseurl . '/servers/eventBlockRule',
                        'controller' => 'servers',
                        'action' => 'eventBlockRule',
                        'requirement' => $this->Acl->canAccess('servers', 'eventBlockRule'),
                        'icon' => 'fas fa-filter-circle-xmark'
                    ],
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
                'id' => 'correlations',
                'label' => __('Correlations'),
                'icon' => 'fas fa-circle-nodes',
                'children' => [
                    [
                        'label' => __('Top correlations'),
                        'url' => $baseurl . '/correlations/top',
                        'controller' => 'correlations',
                        'action' => 'top',
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
            ]
        ];
        return [
            'type' => 'root',
            'id'   => 'administration',
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
            ]
        ];
        return [
                'type' => 'root',
                'id'   => 'logs',
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
        ];

        return [
                'type' => 'root',
                'id'   => 'api',
                'label' => __('API'),
                'icon' => 'fas fa-code',
                'children' => $automationChildren
        ];
    }

    private function buildResourcesMenu(array $context, $baseurl)
    {
        extract($context);

        $smimeCertificate = (string)Configure::read('SMIME.cert_public_sign');
        $resourcesChildren = [
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
            ['divider' => true],
            [
                'label' => __('Server PGP public key'),
                'url' => Configure::read('MISP.download_gpg_from_homedir')
                    ? $baseurl . '/users/getGpgPublicKey'
                    : $baseurl . '/gpg.asc',
                'icon' => 'fas fa-key',
                'requirement' => Configure::read('MISP.download_gpg_from_homedir')
                    || is_file(WWW_ROOT . 'gpg.asc'),
            ],
            [
                'label' => __('Server S/MIME certificate'),
                'url' => $baseurl . '/users/getSmimeCertificate',
                'icon' => 'fas fa-certificate',
                'requirement' => Configure::read('SMIME.enabled')
                    && is_file($smimeCertificate)
                    && is_readable($smimeCertificate),
            ],
            ['divider' => true],
            [
                'type' => 'group',
                'label' => __('Themes'),
                'icon' => 'fas fa-palette',
                'requirement' => !empty($context['themesEnabled']),
                'children' => $this->buildThemesMenu($context)
            ]
        ];
        return [
                'type' => 'root',
                'id'   => 'resources',
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

        $items = [];

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

    /**
     * The News button, which opens the news panel, on the pages the controller
     * gives side panels (AppController::beforeRender sets `sidePanels`).
     */
    private function buildNewsItem(array $context)
    {
        $unread = (int)($context['sidePanels']['news']['unread'] ?? 0);
        return [
            'type' => 'panel',
            'panel' => 'nw-so',
            'id' => 'news',
            'requirement' => !empty($context['sidePanels']['news']),
            'label' => __('News'),
            'count' => $unread ?: null,
            'lit' => $unread > 0,
            'title' => $unread
                ? __n('News: %s unread', 'News: %s unread', $unread, $unread)
                : __('News'),
            'icon' => 'fas fa-newspaper',
        ];
    }

    private function buildBookmarksItem(array $context)
    {
        $page = $context['sidePanels']['bookmarks'];
        return [
            'type' => 'panel',
            'panel' => 'bm-so',
            'id' => 'bookmarks',
            'label' => __('Bookmarks'),
            'count' => null,
            'lit' => !empty($page['lit']),
            'home' => !empty($page['home']),
            'title' => __('Bookmarks'),
            'icon' => 'fas fa-star',
        ];
    }

    /**
     * The analyst graph "Add to graph" feeds, when the controller says this
     * user may have one (AppController::beforeRender sets `intelGraph`).
     */
    private function buildIntelGraphItem(array $context)
    {
        $graph = $context['intelGraph']['active'] ?? null;
        return [
            'type' => 'intelGraph',
            'id' => 'intel-graph',
            'requirement' => !empty($context['intelGraph']),
            'label' => $graph ? $graph['name'] : __('No graph'),
            'count' => $graph ? (int)$graph['node_count'] : null,
            'title' => __('Analyst graph'),
            'icon' => 'misp-icon misp-icon-analyst-graph misp-simple',
        ];
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

        $bookmarksChildren[] = [
            'type' => 'setHomepage',
            'label' => __('Set this page as homepage'),
            'icon' => 'fas fa-home'
        ];

        // $bookmarksChildren[] = [
        //     'label' => __('Add Bookmark'),
        //     'url' => $baseurl . '/bookmarks/add',
        //     'controller' => 'bookmarks',
        //     'action' => 'add',
        //     'icon' => 'fas fa-plus'
        // ];
        $bookmarksChildren[] = [
            'label' => __('Manage Bookmarks'),
            'url' => $baseurl . '/bookmarks/index',
            'controller' => 'bookmarks',
            'action' => 'index',
            'icon' => 'fas fa-cog'
        ];

        return [
            'type' => 'root',
            'id'   => 'bookmarks',
            'label' => __('Bookmarks'),
            'icon' => 'fas fa-star',
            'children' => $bookmarksChildren
        ];
    }


    private function buildAccountMenu(array $context, $baseurl)
    {
        extract($context);
        $user_icon = !empty($me['Role']['perm_site_admin']) ? 'misp-icon misp-icon-user3 misp-simple' : 'misp-icon misp-icon-user1 misp-simple';

        $profileChildren = [];
        $themeMenu = $this->buildBootstrapThemeMenu($context);
        if ($themeMenu !== null) {
            $profileChildren[] = $themeMenu;
        }
        // Only a Bootstrap theme with both a light and a dark palette has
        // anything to toggle.
        if ($context['darkModeToggle'] ?? true) {
            $profileChildren[] = [
                'type' => 'darkMode',
                'label' => __('Dark mode'),
                'icon'  => 'fas fa-moon',
            ];
        }
        $profileChildren = array_merge($profileChildren, [
            ['divider' => true],
            [
                'type' => 'tutorial',
                'label' => __('Replay the tutorial'),
                'icon' => 'fas fa-graduation-cap',
            ],
            ['divider' => true],
            [
                'label' => __('My Profile'),
                'url' => $baseurl . '/users/view/me',
                'controller' => 'users',
                'action' => 'view',
                'icon' => $user_icon
            ],
            [
                'label' => __('Log out'),
                'url' => $baseurl . '/users/logout',
                'controller' => 'users',
                'action' => 'logout',
                'icon' => 'fas fa-right-from-bracket'
            ]
        ]);

        $orgLogo = $this->OrgImg->getOrgLogoV2($me, 20);

        // Remove the <a> wrapper of the logo
        $orgLogo = preg_replace('/<a[^>]*>(.*?)<\/a>/i', '$1', $orgLogo);

        return [
            'type' => 'root',
            'id'   => 'account',
            'label' => h($this->UserName->convertEmailToName($me['email'])),
            'image' => $orgLogo,
            'children' => $profileChildren
        ];

    }


    private function buildBootstrapThemeMenu(array $context)
    {
        $current = $context['bootstrapTheme'] ?? null;
        $chosen = !empty($context['bootstrapThemeChosen']);
        $modes = [
            'light' => ['icon' => 'fas fa-sun', 'label' => __('Light')],
            'dark' => ['icon' => 'fas fa-moon', 'label' => __('Dark')],
            'both' => ['icon' => 'fas fa-circle-half-stroke', 'label' => __('Light and dark')],
        ];

        $items = [];
        $visible = 0;
        $currentLabel = null;
        foreach (MispTheme::getBootstrapThemes() as $name => $theme) {
            if ($name === $current) {
                $currentLabel = $theme['label'];
            }
            // Hidden themes ship masked; the dark-mode easter egg in
            // navbar_actions.ctp unmasks them.
            $secret = $theme['hide_from_users']
                && !($chosen && $name === $current);
            $visible += $secret ? 0 : 1;
            $items[] = [
                'type' => 'bootstrapTheme',
                'theme' => $name,
                'label' => $theme['label'],
                'description' => $theme['description'],
                'modeIcon' => $modes[$theme['mode']]['icon'],
                'modeLabel' => $modes[$theme['mode']]['label'],
                'on' => $chosen && $name === $current,
                'secret' => $secret,
            ];
        }
        if ($visible < 2) {
            return null;
        }
        $default = MispTheme::bootstrapTheme();
        array_unshift(
            $items,
            [
                'type' => 'bootstrapTheme',
                'theme' => '',
                'label' => __('Instance default (%s)', $default['label']),
                'description' => __('Follow the theme your administrator picks for this instance.'),
                'modeIcon' => $modes[$default['mode']]['icon'],
                'modeLabel' => $modes[$default['mode']]['label'],
                'on' => !$chosen,
            ],
            ['divider' => true]
        );
        return [
            'label' => __('Theme'),
            'icon' => 'fas fa-palette',
            'value' => $currentLabel,
            'children' => $items,
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

    private function resolveActiveMenu(string $controller, string $action): ?string
    {
        $entry = self::ACTIVE_MENU_MAP[strtolower($controller)] ?? null;
        if ($entry === null) {
            return null;
        }
        if (is_string($entry)) {
            return $entry;
        }
        $action = strtolower($action);
        if (isset($entry[$action])) {
            return $entry[$action];
        }
        if (strpos($action, 'admin_') === 0 && isset($entry['admin_default'])) {
            return $entry['admin_default'];
        }
        return $entry['default'] ?? null;
    }

    private function markActive(array $items, ?string $activeMenuId): array
    {
        if ($activeMenuId === null) {
            return $items;
        }
        foreach ($items as &$item) {
            $item['active'] = !empty($item['id']) && $item['id'] === $activeMenuId;
        }
        return $items;
    }


}
