<?php

namespace App\Controller\Component\Navigation;


class SidemenuNavigation
{
    private $iconTable;
    private $request;

    public function __construct($iconTable, $request)
    {
        $this->iconTable = $iconTable;
        $this->request = $request;
    }

    public function get(): array
    {
        return [
            __('Threat intelligence') => [
                'Events' => [
                    'label' => __('List Events'),
                    'icon' => $this->iconTable['Events'],
                    'url' => '/events/index',
                ],
                'PeriodicReport' => [
                    'label' => __('View Periodic Report'),
                    'icon' => $this->iconTable['PeriodicReport'],
                    'url' => '/users/viewPeriodicSummary/daily',
                ],
                'Dashboard' => [
                    'label' => __('Dashboard'),
                    'icon' => $this->iconTable['Dashboard'],
                    'url' => '/dashboards',
                ],
                'ListExport' => [
                    'label' => __('List & Export'),
                    'icon' => 'list-alt',
                    'children' => [
                        'Attributes' => [
                            'label' => __('List Attributes'),
                            'icon' => $this->iconTable['Attributes'],
                            'url' => '/attributes/index',
                        ],
                        'Proposals' => [
                            'label' => __('List Proposals'),
                            'icon' => $this->iconTable['Proposals'],
                            'url' => '/shadow_attributes/index/all:0',
                        ],
                        'Delegation' => [
                            'label' => __('View Delegations'),
                            'icon' => $this->iconTable['Events'],
                            'url' => 'event_delegations/index/context:pending',
                        ],
                        'Export' => [
                            'label' => __('Export'),
                            'icon' => 'download',
                            'url' => '/events/export',
                        ],
                    ],
                ],
            ],
            __('Directory') => [
                'Organisations' => [
                    'label' => __('Organisations'),
                    'icon' => $this->iconTable['Organisations'],
                    'url' => '/organisations/index',
                ],
                'SharingGroups' => [
                    'label' => __('Sharing Groups'),
                    'icon' => $this->iconTable['SharingGroups'],
                    'url' => '/sharing-groups/index',
                ],
            ],
            __('Knowledge Base') => [
                'Tags' => [
                    'label' => __('Tags'),
                    'icon' => $this->iconTable['Tags'],
                    'url' => '/tags/index',
                ],
                'Taxonomies' => [
                    'label' => __('Taxonomies'),
                    'icon' => $this->iconTable['Taxonomies'],
                    'url' => '/taxonomies/index',
                ],
                'Galaxies' => [
                    'label' => __('Galaxies'),
                    'icon' => $this->iconTable['Galaxies'],
                    'url' => '/galaxies/index',
                ],
                'Templates' => [
                    'label' => __('Templates'),
                    'icon' => 'ruler',
                    'children' => [
                        'ObjectTemplates' => [
                            'label' => __('Object Templates'),
                            'icon' => $this->iconTable['ObjectTemplates'],
                            'url' => '/object-templates/index',
                        ],
                        'TagCollections' => [
                            'label' => __('Tag Collections'),
                            'icon' => $this->iconTable['TagCollections'],
                            'url' => '/tag_collections/index',
                        ],
                        'Templates' => [
                            'label' => __('List Templates'),
                            'icon' => $this->iconTable['Templates'],
                            'url' => '/templates/index',
                        ],
                    ],
                ],
            ],
            __('Behaviors') => [
                'Warninglists' => [
                    'label' => __('Warninglists'),
                    'icon' => $this->iconTable['Warninglists'],
                    'url' => '/warninglists/index',
                ],
                'Workflows' => [
                    'label' => __('Workflows'),
                    'icon' => $this->iconTable['Workflows'],
                    'url' => '/workflows/index',
                ],
                'Input/Output Filters' => [
                    'label' => __('Input Filters'),
                    'icon' => 'filter',
                    'children' => [
                        'CorrelationsExclusions' => [
                            'label' => __('Correlation Exclusions'),
                            'icon' => $this->iconTable['CorrelationsExclusions'],
                            'url' => '/correlation_exclusions/index',
                        ],
                        'DecayingModels' => [
                            'label' => __('Decaying Models'),
                            'icon' => $this->iconTable['DecayingModels'],
                            'url' => '/decayingModel/index',
                        ],
                        'ImportRegexp' => [
                            'label' => __('Import Regexp'),
                            'icon' => $this->iconTable['ImportRegexp'],
                            'url' => '/admin/regexp/index',
                        ],
                        'SignatureAllowedlists' => [
                            'label' => __('Signature Allowedlists'),
                            'icon' => $this->iconTable['SignatureAllowedlists'],
                            'url' => '/admin/allowedlists/index',
                        ],
                        'NoticeLists' => [
                            'label' => __('NoticeLists'),
                            'icon' => $this->iconTable['Noticelists'],
                            'url' => '/noticelists/index',
                        ],
                    ]
                ],
                'Correlations' => [
                    'label' => __('Correlations'),
                    'icon' => $this->iconTable['Correlations'],
                    'url' => '/correlation_exclusions/index',
                ],
            ],
            __('Synchronisation') => [
                'Servers' => [
                    'label' => __('List Servers'),
                    'icon' => $this->iconTable['Servers'],
                    'url' => '/servers/index',
                ],
                'Feeds' => [
                    'label' => __('List Feeds'),
                    'icon' => $this->iconTable['Feeds'],
                    'url' => '/feeds/index',
                ],
                'Communities' => [
                    'label' => __('Communities'),
                    'icon' => 'handshake',
                    'children' => [
                        'Communities' => [
                            'label' => __('Communities'),
                            'icon' => $this->iconTable['Communities'],
                            'url' => '/communities/index',
                        ],
                        'Cerebrates' => [
                            'label' => __('Cerebrate'),
                            'icon' => $this->iconTable['Cerebrates'],
                            'url' => '/cerebrates/index',
                        ],
                        'TaxiiServers' => [
                            'label' => __('Taxii Servers'),
                            'icon' => $this->iconTable['TaxiiServers'],
                            'url' => '/TaxiiServers/index',
                        ],
                    ],
                ],
            ],
            __('Administration') => [
                'Users' => [
                    'label' => __('Users'),
                    'icon' => $this->iconTable['Users'],
                    'url' => '/admin/users/index',
                ],
                'Roles' => [
                    'label' => __('Roles'),
                    'icon' => $this->iconTable['Roles'],
                    'url' => '/roles/index',
                ],
                'Messages' => [
                    'label' => __('Inbox'),
                    'icon' => $this->iconTable['Inbox'],
                    'url' => '/inbox/index',
                ],
                'ServerSettings' => [
                    'label' => __('Settings & Maintenance'),
                    'icon' => $this->iconTable['ServerSettings'],
                    'url' => '/servers/serverSettings',
                ],
                'Jobs' => [
                    'label' => __('Jobs'),
                    'icon' => $this->iconTable['Jobs'],
                    'url' => '/jobs/index',
                ],
                'BlockRules' => [
                    'label' => __('Block Rules'),
                    'icon' => $this->iconTable['BlockRules'],
                    'children' => [
                        'EventsBlockRules' => [
                            'label' => __('Events Block Rules'),
                            'icon' => $this->iconTable['EventsBlockRules'],
                            'url' => '/eventBlocklists',
                        ],
                        'OrganisationsRules' => [
                            'label' => __('Organisations Rules'),
                            'icon' => $this->iconTable['OrganisationsRules'],
                            'url' => '/orgBlocklists',
                        ],
                    ],
                ],
                'Logs' => [
                    'label' => __('Logs'),
                    'icon' => $this->iconTable['Logs'],
                    'children' => [
                        'ApplicationLogs' => [
                            'label' => __('Application Logs'),
                            'icon' => $this->iconTable['ApplicationLogs'],
                            'url' => '/logs/index',
                        ],
                        'AccessLogs' => [
                            'label' => __('Access Logs'),
                            'icon' => $this->iconTable['AccessLogs'],
                            'url' => '/admin/access_logs/index',
                        ],
                    ]
                ],
                'RestClient' => [
                    'label' => __('REST Client'),
                    'icon' => $this->iconTable['RestClient'],
                    'url' => '/api/rest',
                ],
                'Statistics' => [
                    'label' => __('Statistics'),
                    'icon' => 'chart-pie',
                    'url' => '/users/statistics',
                ],
            ],
            __('Documentation') => [
                'API' => [
                    'label' => __('Open API'),
                    'icon' => $this->iconTable['API'],
                    'url' => '/api/openapi',
                ],
                'UserGuide' => [
                    'label' => __('User Guide'),
                    'icon' => 'book-open',
                    'url' => 'https://www.circl.lu/doc/misp/',
                ],
                'Data Model' => [
                    'label' => __('Data Model'),
                    'icon' => 'shapes',
                    'url' => '/pages/display/doc/categories_and_types',
                ],
                'TermsConditions' => [
                    'label' => __('Terms & Conditions'),
                    'icon' => 'gavel',
                    'url' => '/users/terms',
                ],
            ]
        ];
    }

    #public function get(): array
    #{
    #    return [
    #        __('Threat Intel') => [
    #            'Data' => [
    #                'label' => __('Data'),
    #                'icon' => $this->iconTable['Events'],
    #                'url' => '/events/index',
    #                'children' => [
    #                    'events' => [
    #                        'url' => '/Events/index',
    #                        'label' => __('Events'),
    #                    ],
    #                    'attributes' => [
    #                        'url' => '/attributes/index',
    #                        'label' => __('Attributes'),
    #                    ],
    #                    'objects' => [
    #                        'url' => '/objects/index',
    #                        'label' => __('Objects'),
    #                    ],
    #                ]
    #            ],
    #            'Context' => [
    #                'label' => __('Context'),
    #                'icon' => $this->iconTable['Context'],
    #                'url' => '/galaxies/index',
    #                'children' => [
    #                    'galaxies' => [
    #                        'url' => '/galaxies/index',
    #                        'label' => __('Galaxies')
    #                    ],
    #                    'taxonomies' => [
    #                        'url' => '/taxonomies/index',
    #                        'label' => __('Taxonomies')
    #                    ],
    #                    'tags' => [
    #                        'url' => '/tags/index',
    #                        'label' => __('Tags')
    #                    ]
    #                ]
    #            ],
    #            'Insights' => [
    #                'label' => __('Insights'),
    #                'icon' => $this->iconTable['Insights'],
    #                'url' => '/dashboards/index',
    #                'children' => [
    #                    'galaxies' => [
    #                        'url' => '/galaxies/index',
    #                        'label' => __('Galaxies')
    #                    ],
    #                    'galaxy_relationships' => [
    #                        'url' => '/galaxy_cluster_relations/index',
    #                        'label' => __('Relationships')
    #                    ],
    #                    'taxonomies' => [
    #                        'url' => '/taxonomies/index',
    #                        'label' => __('Taxonomies')
    #                    ],
    #                    'tags' => [
    #                        'url' => '/tags/index',
    #                        'label' => __('Tags')
    #                    ],
    #                    'tag_collections' => [
    #                        'url' => '/tag_collections/index',
    #                        'label' => __('Tag Collections')
    #                    ]
    #                ]
    #            ],
    #        ],
    #        __('Community') => [
    #            'Organisations' => [
    #                'label' => __('Organisations'),
    #                'icon' => $this->iconTable['Organisations'],
    #                'url' => '/organisations/index',
    #            ],
    #            'SharingGroups' => [
    #                'label' => __('Sharing Groups'),
    #                'icon' => $this->iconTable['SharingGroups'],
    #                'url' => '/sharingGroups/index',
    #            ],
    #        ],
    #        __('Connectivity') => [
    #            'Connectivity' => [
    #                'label' => __('Connectivity'),
    #                'icon' => $this->iconTable['Connectivity'],
    #                'children' => [
    #                    'servers' => [
    #                        'url' => '/servers/index',
    #                        'label' => __('Servers'),
    #                    ],
    #                    'feeds' => [
    #                        'url' => '/feeds/index',
    #                        'label' => __('Feeds'),
    #                    ],
    #                    'cerebrates' => [
    #                        'url' => '/cerebrates/index',
    #                        'label' => __('Cerebrates'),
    #                    ]
    #                ]
    #            ]
    #        ],
    #        __('Administration') => [
    #            'Roles' => [
    #                'label' => __('Roles'),
    #                'icon' => $this->iconTable['Roles'],
    #                'url' => '/roles/index',
    #            ],
    #            'Users' => [
    #                'label' => __('Users'),
    #                'icon' => $this->iconTable['Users'],
    #                'url' => '/users/index',
    #            ],
    #            'UserSettings' => [
    #                'label' => __('Users Settings'),
    #                'icon' => $this->iconTable['UserSettings'],
    #                'url' => '/user-settings/index',
    #            ],
    #            'Messages' => [
    #                'label' => __('Messages'),
    #                'icon' => $this->iconTable['Inbox'],
    #                'url' => '/inbox/index',
    #                'children' => [
    #                    'inbox' => [
    #                        'url' => '/inbox/index',
    #                        'label' => __('Inbox'),
    #                    ],
    #                    'outbox' => [
    #                        'url' => '/outbox/index',
    #                        'label' => __('Outbox'),
    #                    ],
    #                ]
    #            ],
    #            'Instance' => [
    #                'label' => __('Instance'),
    #                'icon' => $this->iconTable['Instance'],
    #                'children' => [
    #                    'Settings' => [
    #                        'label' => __('Settings'),
    #                        'url' => '/instance/settings',
    #                        'icon' => 'cogs',
    #                    ],
    #                    'Database' => [
    #                        'label' => __('Database'),
    #                        'url' => '/instance/migrationIndex',
    #                        'icon' => 'database',
    #                    ],
    #                    'AuditLogs' => [
    #                        'label' => __('Audit Logs'),
    #                        'url' => '/auditLogs/index',
    #                        'icon' => 'history',
    #                    ]
    #                ]
    #            ],
    #            'API' => [
    #                'label' => __('API'),
    #                'icon' => $this->iconTable['API'],
    #                'url' => '/api/index',
    #            ],
    #        ]
    #    ];
    #}
}
