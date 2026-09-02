<?php
// Title of the index displayed in the header section, leaving it empty will fallback to controller name
$headerTitle = __('');

// Description displayed under the title in the header section, leave empty if not needed
$headerDescription = __('');

// Actions displayed as buttons in the header section, leave empty if not needed
$headerActions = [];
if ($this->Acl->canAccess('cerebrates', 'index')) {
    $headerActions[] = [
        'type' => 'navigate',
        'label' => __('List Cerebrates'),
        'icon' => 'globe',
        'url' => $baseurl . '/cerebrates/index'
    ];
}

if ($this->Acl->canAccess('communities', 'index')) {
    $headerActions[] = [
        'type' => 'navigate',
        'label' => __('List Communities'),
        'icon' => 'users',
        'url' => $baseurl . '/communities/index'
    ];
}

if ($this->Acl->canAccess('servers', 'add')) {
    $headerActions[] = [
        'type' => 'modal',
        'label' => __('Add Server'),
        'icon' => 'plus',
        'url' => $baseurl . '/servers/add'
    ];
}


$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);


$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Server.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Server.id',
        'data_path' => 'Server.id',
        'element' => 'id',
        'url' => $baseurl . '/servers/previewIndex/%id%',
        'display_in' => ['table']
    ],
    [
        'name' => __('Name'),
        'sort' => 'Server.name',
        'data_path' => 'Server',
        'element' => 'server_name',
        'display_in' => ['table']
    ],
    // [
    //     'name' => __('Prio'),
    //     'sort' => 'Server.priority',
    //     'data_path' => 'Server.id',
    //     'element' => 'server_prio',
    //     'display_in' => ['table']
    // ],
    [
        'name' => __('Connection test'),
        'element' => 'server_action_button',
        'button' => [
            'label' => __('Run'),
            'js_action' => 'testConnection',
            'js_param_path' => 'Server.id',
            'cell_id' => 'connection_test_%s',
            'cell_id_param_path' => 'Server.id',
            'result_id' => 'connection_test_result_%s',
            'title' => __('Test remote instance connection')
        ],
        'display_in' => ['table']
    ],
    [
        'name' => __('Sync user'),
        'element' => 'server_action_button',
        'button' => [
            'label' => __('View'),
            'js_action' => 'getRemoteSyncUser',
            'js_param_path' => 'Server.id',
            'cell_id' => 'sync_user_test_%s',
            'cell_id_param_path' => 'Server.id',
            'result_id' => 'sync_user_test_result_%s',
            'title' => __('View remote sync user')
        ],
        'display_in' => ['table']
    ],
    [
        'name' => __('Internal'),
        'sort' => 'Server.internal',
        'data_path' => 'Server.internal',
        'element' => 'server_boolean',
        'true' => __('Internal'),
        'false' => __('Not internal'),
        'display_in' => ['table']
    ],
    [
        'name' => __('Push rules'),
        'sort' => 'Server.push',
        'element' => 'server_push_pull',
        'mode' => 'push',
        'display_in' => ['table']
    ],
    [
        'name' => __('Pull rules'),
        'sort' => 'Server.pull',
        'element' => 'server_push_pull',
        'mode' => 'pull',
        'display_in' => ['table']
    ],
    [
        'name' => __('Sightings'),
        'sort' => 'Server.push_sightings',
        'data_path' => 'Server.push_sightings',
        'element' => 'server_boolean',
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'display_in' => ['table']
    ],
    [
        'name' => __('Clusters'),
        'sort' => 'Server.push_galaxy_clusters',
        'data_path' => 'Server.push_galaxy_clusters',
        'element' => 'server_boolean',
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'display_in' => ['table']
    ],
    [
        'name' => __('Analyst data'),
        'sort' => 'Server.push_analyst_data',
        'data_path' => 'Server.push_analyst_data',
        'element' => 'server_boolean',
        'true' => __('Enabled'),
        'false' => __('Disabled'),
        'display_in' => ['table']
    ],
    [
        'name' => __('Cache'),
        'sort' => 'Server.caching_enabled',
        'data_path' => 'Server',
        'element' => 'server_cache_status',
        'display_in' => ['table']
    ],
    [
        'name' => __('Organisations'),
        'data_path' => '',
        'element' => 'server_organisations',
        'display_in' => ['table']
    ],
    [
        'name' => __('Options'),
        'data_path' => 'Server',
        'element' => 'server_options',
        'display_in' => ['table']
    ],
    [
        'name' => __('Cert files'),
        'data_path' => 'Server',
        'element' => 'server_cert_files',
        'display_in' => ['table']
    ],
    [
        'name' => __('Bound sync users'),
        'data_path' => 'BoundUsers',
        'element' => 'server_bound_users',
        'display_in' => ['table']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Server.id',
        'card_section' => 'extra',
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('Explore server'),
                'icon' => 'compass',
                'url' => $baseurl . '/servers/previewIndex/%id%',
            ],
            [
                'type' => 'postLink',
                'label' => __('Pull all'),
                'icon' => 'arrow-circle-down',
                'url' => $baseurl . '/servers/pull/%id%/full',
                'confirm' => __('Are you sure you want to pull all events from this server?'),
                'requirement' => function (array $row) {
                    return !empty($row['Server']['pull']);
                }
            ],
            [
                'type' => 'postLink',
                'label' => __('Push all'),
                'icon' => 'arrow-circle-up',
                'url' => $baseurl . '/servers/push/%id%/full',
                'confirm' => __('Are you sure you want to push all events to this server?'),
                'requirement' => function (array $row) {
                    return !empty($row['Server']['push']);
                }
            ],
            [
                'type' => 'postLink',
                'label' => __('Cache instance'),
                'icon' => 'database',
                'url' => $baseurl . '/servers/cache/%id%',
                'confirm' => __('Are you sure you want to cache the contents of this server?'),
                'requirement' => function (array $row) {
                    return !empty($row['Server']['caching_enabled']);
                }
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/servers/edit/%id%',
                'requirement' => $isSiteAdmin
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/servers/deleteSelection/%id%',
                'class' => 'text-danger',
                'requirement' => $isSiteAdmin
            ]
        ]
    ]
];


echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $servers,
            'primary_id_path' => 'Server.id',
            // Custom card display for servers
            'card_element' => 'Servers/server_card',
            'cards_per_row' => ['' => 1, 'xl' => 2],
            'filter_bar' => [
                'pull' => 'right',
                'children' => [
                    [
                        'type' => 'search',
                        'button' => __('Search'),
                        'placeholder' => __('Search by server name or URL'),
                        'name' => 'search',
                        'mode' => 'legacy',
                    ],
                    [
                        'type' => 'more_filters',
                        'label' => __('More filters'),
                        'children' => [
                            [
                                'type' => 'dropdown',
                                'label' => __('Internal'),
                                'name' => 'internal',
                                'options' => [
                                    '1' => __('Yes'),
                                    '0' => __('No')
                                ]
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Push enabled'),
                                'name' => 'push',
                                'options' => [
                                    '1' => __('Yes'),
                                    '0' => __('No')
                                ]
                            ],
                            [
                                'type' => 'dropdown',
                                'label' => __('Pull enabled'),
                                'name' => 'pull',
                                'options' => [
                                    '1' => __('Yes'),
                                    '0' => __('No')
                                ]
                            ]
                        ]
                    ],
                ],
                'delete' => '/deleteSelection'
            ],
            'fields' => $fields,
        ]
    ],
    'item_url' => '/servers'
]);
?>
<script>
(function () {
    var LABELS = <?= json_encode([
        'pending' => __('Not tested'),
        'running' => __('Testing…'),
        'ok' => __('Connected'),
        'down' => __('Unreachable'),
    ]) ?>;

    var MAX_IN_FLIGHT = 2;
    var queue = [];
    var running = 0;

    function pump() {
        while (running < MAX_IN_FLIGHT && queue.length > 0) {
            running++;
            Promise.resolve(queue.shift()()).catch(function () {}).then(function () {
                running--;
                pump();
            });
        }
    }

    function probe(id, kind) {
        var panel = document.getElementById(
            (kind === 'connection' ? 'srv-conn-' : 'srv-sync-') + id
        );
        if (!panel) return;
        panel.removeAttribute('data-probe-state');
        queue.push(function () {
            return kind === 'connection'
                ? testConnection(id, panel)
                : getRemoteSyncUser(id, panel);
        });
        pump();
    }

    function setPanelState(prefix, detail) {
        var panel = document.getElementById(prefix + detail.id);
        if (!panel) return;
        if (detail.state === 'down') {
            panel.setAttribute('data-probe-state', 'down');
        } else {
            panel.removeAttribute('data-probe-state');
        }
    }

    // The connection test is what the header verdict speaks for; the sync user
    // probe only dresses its own panel.
    document.addEventListener('misp:server-connection', function (ev) {
        setPanelState('srv-conn-', ev.detail);
        var card = document.querySelector(
            '.srv-card[data-server-id="' + ev.detail.id + '"]'
        );
        if (!card) return;
        var state = ev.detail.state || 'pending';
        card.setAttribute('data-srv-state', state);
        var text = card.querySelector('.srv-status-text');
        if (text && LABELS[state]) text.textContent = LABELS[state];
    });

    document.addEventListener('misp:server-sync-user', function (ev) {
        setPanelState('srv-sync-', ev.detail);
    });

    document.addEventListener('click', function (ev) {
        var retry = ev.target.closest('.srv-retry');
        if (retry) {
            ev.preventDefault();
            probe(retry.dataset.serverId, retry.dataset.probe);
            return;
        }

        var reset = ev.target.closest('.srv-reset-key');
        if (!reset) return;
        ev.preventDefault();
        var id = reset.dataset.serverId;
        showConfirmModal({
            title: <?= json_encode(__('Reset the API key?')) ?>,
            body: <?= json_encode(__('A new sync key will be generated on the remote instance and stored here. The current key stops working immediately.')) ?>
                + ' <strong>' + escapeHtml(reset.dataset.serverName || '') + '</strong>',
            confirmLabel: <?= json_encode(__('Reset key')) ?>,
            confirmClass: 'btn-danger',
            onConfirm: function () {
                var poster = document.getElementById('srv-reset-key-' + id);
                if (poster) poster.click();
            }
        });
    });

    document.addEventListener('DOMContentLoaded', function () {
        var cards = document.querySelectorAll('.srv-card[data-server-id]');
        if (cards.length === 0) return;

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                observer.unobserve(entry.target);
                probe(entry.target.dataset.serverId, 'connection');
                probe(entry.target.dataset.serverId, 'sync-user');
            });
        }, { rootMargin: '120px' });

        cards.forEach(function (card) { observer.observe(card); });
    });
}());
</script>
