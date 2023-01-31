<?php
namespace SidemenuNavigation;

use Cake\Core\Configure;

class Sidemenu {
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
            __('Threat Intel') => [
                'Data' => [
                    'label' => __('Data'),
                    'icon' => $this->iconTable['Events'],
                    'url' => '/events/index',
                    'children' => [
                        'events' => [
                            'url' => '/Events/index',
                            'label' => __('Events'),
                        ],
                        'attributes' => [
                            'url' => '/attributes/index',
                            'label' => __('Attributes'),
                        ],
                        'objects' => [
                            'url' => '/objects/index',
                            'label' => __('Objects'),
                        ],
                    ]
                ],
                'Context' => [
                    'label' => __('Context'),
                    'icon' => $this->iconTable['Context'],
                    'url' => '/galaxies/index',
                    'children' => [
                        'galaxies' => [
                            'url' => '/galaxies/index',
                            'label' => __('Galaxies')
                        ],
                        'taxonomies' => [
                            'url' => '/taxonomies/index',
                            'label' => __('Taxonomies')
                        ],
                        'tags' => [
                            'url' => '/tags/index',
                            'label' => __('Tags')
                        ]
                    ]
                ],
                'Insights' => [
                    'label' => __('Insights'),
                    'icon' => $this->iconTable['Insights'],
                    'url' => '/dashboards/index',
                    'children' => [
                        'galaxies' => [
                            'url' => '/galaxies/index',
                            'label' => __('Galaxies')
                        ],
                        'galaxy_relationships' => [
                            'url' => '/galaxy_cluster_relations/index',
                            'label' => __('Relationships')
                        ],
                        'taxonomies' => [
                            'url' => '/taxonomies/index',
                            'label' => __('Taxonomies')
                        ],
                        'tags' => [
                            'url' => '/tags/index',
                            'label' => __('Tags')
                        ],
                        'tag_collections' => [
                            'url' => '/tag_collections/index',
                            'label' => __('Tag Collections')
                        ]
                    ]
                ],
            ],
            __('Community') => [
                'Organisations' => [
                    'label' => __('Organisations'),
                    'icon' => $this->iconTable['Organisations'],
                    'url' => '/organisations/index',
                ],
                'SharingGroups' => [
                    'label' => __('Sharing Groups'),
                    'icon' => $this->iconTable['SharingGroups'],
                    'url' => '/sharingGroups/index',
                ],
            ],
            __('Connectivity') => [
                'Connectivity' => [
                    'label' => __('Connectivity'),
                    'icon' => $this->iconTable['Connectivity'],
                    'children' => [
                        'servers' => [
                            'url' => '/servers/index',
                            'label' => __('Servers'),
                        ],
                        'feeds' => [
                            'url' => '/feeds/index',
                            'label' => __('Feeds'),
                        ],
                        'cerebrates' => [
                            'url' => '/cerebrates/index',
                            'label' => __('Cerebrates'),
                        ]
                    ]
                ]
            ],
            __('Administration') => [
                'Roles' => [
                    'label' => __('Roles'),
                    'icon' => $this->iconTable['Roles'],
                    'url' => '/roles/index',
                ],
                'Users' => [
                    'label' => __('Users'),
                    'icon' => $this->iconTable['Users'],
                    'url' => '/users/index',
                ],
                'UserSettings' => [
                    'label' => __('Users Settings'),
                    'icon' => $this->iconTable['UserSettings'],
                    'url' => '/user-settings/index',
                ],
                'Messages' => [
                    'label' => __('Messages'),
                    'icon' => $this->iconTable['Inbox'],
                    'url' => '/inbox/index',
                    'children' => [
                        'inbox' => [
                            'url' => '/inbox/index',
                            'label' => __('Inbox'),
                        ],
                        'outbox' => [
                            'url' => '/outbox/index',
                            'label' => __('Outbox'),
                        ],
                    ]
                ],
                'Instance' => [
                    'label' => __('Instance'),
                    'icon' => $this->iconTable['Instance'],
                    'children' => [
                        'Settings' => [
                            'label' => __('Settings'),
                            'url' => '/instance/settings',
                            'icon' => 'cogs',
                        ],
                        'Database' => [
                            'label' => __('Database'),
                            'url' => '/instance/migrationIndex',
                            'icon' => 'database',
                        ],
                        'AuditLogs' => [
                            'label' => __('Audit Logs'),
                            'url' => '/auditLogs/index',
                            'icon' => 'history',
                        ]
                    ]
                ],
                'API' => [
                    'label' => __('API'),
                    'icon' => $this->iconTable['API'],
                    'url' => '/api/index',
                ],
            ]
        ];
    }
}
