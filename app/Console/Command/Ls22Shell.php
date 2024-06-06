<?php
class Ls22Shell extends AppShell
{
    public $uses = ['Server'];
    private $__servers = [];

    private function __getInstances($path)
    {
        if (empty($path)) {
             $path = 'instances.csv';
        }
        $file = file_get_contents($path);
        $lines = explode(PHP_EOL, $file);
        foreach ($lines as $k => $line) {
            if ($k === 0) {
                continue;
            }
            $fields = explode(',', $line);
            if (count($fields) === 4 && $fields[1] === 'admin@admin.test') {
                $this->__servers[] = [
                    'Server' => [
                        'url' => trim($fields[0]),
                        'authkey' => trim($fields[2]),
                        'self_signed' => true,
                    ]
                ];
            }
        }
    }

    public function getOptionParser()
    {
        $this->stdout->styles('green', array('text' => 'green'));
        $this->stdout->styles('black', array('text' => 'black'));

        $parser = parent::getOptionParser();
        $parser->addSubcommand('enableTaxonomy', [
            'help' => __('Enable a taxonomy with all its tags.'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ],
                    'taxonomy' => [
                        'help' => 'The name of the taxonomy to enable, such as "tlp"',
                        'short' => 't',
                        'required' => true
                    ],
                    'misp_url_filter' => [
                        'help' => 'The url of the instance to enable it for - otherwise all are selected',
                        'short' => 'm',
                        'required' => false
                    ]
                ),
            ),
        ]);
        $parser->addSubcommand('checkSyncConnections', [
            'help' => __('Check the given sync connection(s) for the given server(s).'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ],
                    'misp_url_filter' => [
                        'help' => 'The url of the instance to execute changes on. If not set, all are updated.',
                        'short' => 'm',
                        'required' => false
                    ],
                    'synced_misp_url_filter' => [
                        'help' => 'The sync connection to modify on each valid instance (as selected by the misp_url_filter). If not set, all sync connections on the selected instances will be updated.',
                        'short' => 's',
                        'required' => false
                    ]
                ),
            ),
        ]);
        $parser->addSubcommand('modifySyncConnection', [
            'help' => __('Modify sync connection(s).'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ],
                    'misp_url_filter' => [
                        'help' => 'The url of the instance to execute changes on. If not set, all are updated.',
                        'short' => 'm',
                        'required' => false
                    ],
                    'synced_misp_url_filter' => [
                        'help' => 'The sync connection to modify on each valid instance (as selected by the misp_url_filter). If not set, all sync connections on the selected instances will be updated.',
                        'short' => 's',
                        'required' => false
                    ],
                    'json' => [
                        'help' => 'JSON delta to push (such as \'{"push": 1}\').',
                        'short' => 'j',
                        'required' => true
                    ]
                ),
            ),
        ]);
        $parser->addSubcommand('setSetting', [
            'help' => __('Set a setting on the given MISP instance(s).'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ],
                    'misp_url_filter' => [
                        'help' => 'The url of the instance to execute changes on. If not set, all are updated.',
                        'short' => 'm',
                        'required' => false
                    ],
                    'setting' => [
                        'help' => 'The setting to modify',
                        'short' => 's',
                        'required' => true
                    ],
                    'value' => [
                        'help' => 'The value to set for the given setting',
                        'short' => 'v',
                        'required' => true
                    ]
                ),
            ),
        ]);
        $parser->addSubcommand('addWarninglist', [
            'help' => __('Inject warninglist'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ],
                    'warninglist' => [
                        'help' => 'Path to the warninglist file',
                        'short' => 'w',
                        'required' => true
                    ]
                ),
            ),
        ]);
        $parser->addSubcommand('status', [
            'help' => __('Check if the instances are available / the API key works.'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ]
                ),
            ),
        ]);
        $parser->addSubcommand('scores', [
            'help' => __('Generate the scores for all BTs.'),
            'parser' => array(
                'options' => array(
                    'instances' => [
                        'help' => 'Path to the instance file, by default "instances.csv" from the local directory',
                        'short' => 'i',
                        'required' => true
                    ],
                    'server_url' => [
                        'help' => 'URL of the server to query for the scores. If nothing is specified, the first valid entry from instances.csv is taken.',
                        'short' => 's',
                        'required' => false
                    ],
                    'from' => [
                        'help' => 'Lower bound of the date. Accepts timestamp or date distance (such as 1d or 5h). Defaults to unbounded.',
                        'short' => 'f',
                        'required' => false
                    ],
                    'to' => [
                        'help' => 'Upper bound of the date. Accepts timestamp or date distance (such as 1d or 5h). Defaults to unbounded.',
                        'short' => 't',
                        'required' => false
                    ],
                    'org' => [
                        'help' => 'Name the org that should be evaluated. If not set, all will be included.',
                        'short' => 'o',
                        'required' => false
                    ]
                ),
            ),
        ]);
        return $parser;
    }

    public function checkSyncConnections()
    {
        $this->__getInstances($this->param('instances'));
        $results = [];
        $instanceFilter = $this->param('misp_url_filter');
        $syncedInstanceFilter = $this->param('synced_misp_url_filter');
        foreach ($this->__servers as $server) {
            if (!empty($instanceFilter) && strtolower(trim($server['Server']['url'])) !== strtolower(trim($instanceFilter))) {
                continue;
            }
            $HttpSocket = $this->Server->setupHttpSocket($server, null);
            $request = $this->Server->setupSyncRequest($server, 'Server');
            $start_time = microtime(true);
            $response = $HttpSocket->get($server['Server']['url'] . '/servers/index', false, $request);
            $baseline = round((microtime(true) - $start_time) * 1000);
            if (!$response->isOk()) {
                $this->out($server['Server']['url'] . ': ' . '<error>Connection or auth failed</error>', 1, Shell::NORMAL);
                continue;
            }
            $synced_servers = json_decode($response->body, true);
            foreach ($synced_servers as $synced_server) {
                $success = false;
                if (empty($syncedInstanceFilter) || strtolower($synced_server['Server']['url']) === strtolower($syncedInstanceFilter)) {
                    $start_time = microtime(true);
                    $response = $HttpSocket->get($server['Server']['url'] . '/servers/testConnection/' . $synced_server['Server']['id'], '{}', $request);
                    $execution_time = round((microtime(true) - $start_time) * 1000) - $baseline;
                    if ($response->isOk()) {
                        $success = true;
                    }
                    $this->out(
                        sprintf(
                            '%s connection to %s: %s (%sms)',
                            $server['Server']['url'],
                            $synced_server['Server']['url'],
                            sprintf(
                                '<%s>%s</%s>',
                                $success ? 'info' : 'error',
                                $success ? 'Success' : 'Failed',
                                $success ? 'info' : 'error'
                            ),
                            $execution_time
                        ),
                        1,
                        Shell::NORMAL
                    );
                }
            }
        }
    }

    public function modifySyncConnection()
    {
        $this->__getInstances($this->param('instances'));
        $results = [];
        $instanceFilter = $this->param('misp_url_filter');
        $syncedInstanceFilter = $this->param('synced_misp_url_filter');
        $json = $this->param('json');
        foreach ($this->__servers as $server) {
            if (!empty($instanceFilter) && strtolower(trim($server['Server']['url'])) !== strtolower(trim($instanceFilter))) {
                continue;
            }
            $HttpSocket = $this->Server->setupHttpSocket($server, null);
            $request = $this->Server->setupSyncRequest($server, 'Server');
            $response = $HttpSocket->get($server['Server']['url'] . '/servers/index', false, $request);
            if (!$response->isOk()) {
                $this->out($server['Server']['url'] . ': ' . '<error>Connection or auth failed</error>', 1, Shell::NORMAL);
            }
            $synced_servers = json_decode($response->body, true);
            $success = false;
            foreach ($synced_servers as $synced_server) {
                if (empty($syncedInstanceFilter) || strtolower($synced_server['Server']['url']) === strtolower($syncedInstanceFilter)) {
                    debug($json);
                    $response = $HttpSocket->post($server['Server']['url'] . '/servers/edit/' . $synced_server['Server']['id'], $json, $request);
                    debug($response->body);
                    if ($response->isOk()) {
                        $success = true;
                    }
                    $this->out(
                        sprintf(
                            '%s connection to %s: %s',
                            $server['Server']['url'],
                            $synced_server['Server']['url'],
                            sprintf(
                                '<%s>%s</%s>',
                                $success ? 'info' : 'error',
                                $success ? 'Success' : 'Failed',
                                $success ? 'info' : 'error'
                            )
                        ),
                        1,
                        Shell::NORMAL
                    );
                }
            }
        }
    }

    public function enableTaxonomy()
    {
        $taxonomyToEnable = $this->param('taxonomy');
        $instanceFilter = $this->param('misp_url_filter');
        if (empty($taxonomyToEnable)) {
            $this->error('No taxonomy provided', 'Provide a taxonomy by specifying the -t or --taxonomy options.');
        }
        $this->__getInstances($this->param('instances'));
        $results = [];
        foreach ($this->__servers as $server) {
            if (!empty($instanceFilter) && strtolower(trim($server['Server']['url'])) !== strtolower(trim($instanceFilter))) {
                continue;
            }
            $HttpSocket = $this->Server->setupHttpSocket($server, null);
            $request = $this->Server->setupSyncRequest($server, 'Server');
            $response = $HttpSocket->get($server['Server']['url'] . '/taxonomies/index', false, $request);
            if (!$response->isOk()) {
                $this->out($server['Server']['url'] . ': ' . '<error>Connection or auth failed</error>', 1, Shell::NORMAL);
            }
            $taxonomies = json_decode($response->body, true);
            $success = false;
            foreach ($taxonomies as $taxonomy) {
                if ($taxonomy['Taxonomy']['namespace'] === $taxonomyToEnable) {
                    $response = $HttpSocket->post($server['Server']['url'] . '/taxonomies/enable/' . $taxonomy['Taxonomy']['id'], '{}', $request);
                    if ($response->isOk()) {
                        $response = $HttpSocket->post($server['Server']['url'] . '/taxonomies/addTag/' . $taxonomy['Taxonomy']['id'], '{}', $request);
                        if ($response->isOk()) {
                            $success = true;
                        }
                    }
                }
            }
            $results[$server['Server']['url']] = $success ? 'Success' : 'Failed';
            $statusWrapped = sprintf(
                '<%s>%s</%s>',
                $success ? 'info' : 'error',
                $results[$server['Server']['url']],
                $success ? 'info' : 'error'
            );
            $this->out($server['Server']['url'] . ': ' . $statusWrapped, 1, Shell::NORMAL);
        }
    }

    public function status()
    {
        $this->__getInstances($this->param('instances'));
        $results = [];
        foreach ($this->__servers as $server) {
            $HttpSocket = $this->Server->setupHttpSocket($server, null);
            $request = $this->Server->setupSyncRequest($server, 'Server');
            $start_time = microtime(true);
            $fatal_error = false;
            try {
                $response = $HttpSocket->get($server['Server']['url'] . '/users/view/me', false, $request);
            } catch (Exception $e) {
                $fatal_error = true;
                echo "\x07";
                $statusWrapped = sprintf(
                    '<error>%s %s: %s</error>',
                    'Something went wrong while trying to reach',
                    $server['Server']['url'],
                    $e->getMessage()
                );
            }
            if (!$fatal_error) {
                $execution_time = round((microtime(true) - $start_time) * 1000);
                $statusWrapped = sprintf(
                    '<%s>%s</%s>',
                    $response->isOk() ? 'info' : 'error',
                    $response->isOk() ? 'OK (' . $execution_time . 'ms)' : 'Failed. (' . $response->code . ')',
                    $response->isOk() ? 'info' : 'error'
                );
            }
            $this->out($server['Server']['url'] . ': ' . $statusWrapped, 1, Shell::NORMAL);
        }
    }

    public function addWarninglist()
    {
        $path = $this->param('warninglist');
        if (empty($path)) {
            $this->error('No warninglist provided', 'Provide a path to a file containing a warninglist JSON by specifying the -w or --warninglist options.');
        }
        $file = file_get_contents($path);
        $this->__getInstances($this->param('instances'));
        $results = [];
        foreach ($this->__servers as $server) {
            $HttpSocket = $this->Server->setupHttpSocket($server, null);
            $request = $this->Server->setupSyncRequest($server, 'Server');
            $start_time = microtime(true);
            $response = $HttpSocket->post($server['Server']['url'] . '/warninglists/add', $file, $request);
            $statusWrapped = sprintf(
                '<%s>%s</%s>',
                $response->isOk() ? 'info' : 'error',
                $response->isOk() ? 'OK' : 'Could not create warninglist',
                $response->isOk() ? 'info' : 'error'
            );
            $this->out($server['Server']['url'] . ': ' . $statusWrapped, 1, Shell::NORMAL);
        }
    }

    public function setSetting()
    {
        $setting = $this->param('setting');
        $value = $this->param('value');
        $this->__getInstances($this->param('instances'));
        foreach ($this->__servers as $server) {
            $HttpSocket = $this->Server->setupHttpSocket($server, null);
            $request = $this->Server->setupSyncRequest($server, 'Server');
            $payload = ["value" => $value];
            $response = $HttpSocket->post($server['Server']['url'] . '/server/serverSettingsEdit/' . $setting, json_encode($value), $request);
            $statusWrapped = sprintf(
                '<%s>%s</%s>',
                $response->isOk() ? 'info' : 'error',
                $response->isOk() ? 'OK' : 'Setting updated',
                $response->isOk() ? 'info' : 'error'
            );
            $this->out($server['Server']['url'] . ': ' . $statusWrapped, 1, Shell::NORMAL);
        }
    }

    public function scores()
    {
        $MITIGATION_DETECTION_OBJECT_UUIDs = [
            'b5acf82e-ecca-4868-82fe-9dbdf4d808c3', # yara
            '3c177337-fb80-405a-a6c1-1b2ddea8684a', # suricata
            'aa21a3cd-ab2c-442a-9999-a5e6626591ec', # sigma
            '6bce7d01-dbec-4054-b3c2-3655a19382e2', # script
            '35b4dd03-4fa9-4e0e-97d8-a2867b11c956', # yabin
        ];
        $results = [];
        $this->__getInstances($this->param('instances'));
        $server = null;
        if (!empty($this->param['server_url'])) {
            foreach ($this->__servers as $temp_server) {
                if ($temp_server['Server']['url'] === $this->param['server_url']) {
                    $server = $temp_server;
                }
            }
        } else {
            $server = $this->__servers[0];
        }
        $HttpSocket = $this->Server->setupHttpSocket($server, null);
        $request = $this->Server->setupSyncRequest($server);
        $response = $HttpSocket->get($server['Server']['url'] . '/organisations/index/scope:local', false, $request);
        $orgs = json_decode($response->body(), true);
        $this->out(__('Organisations fetched. %d found.', count($orgs)), 1, Shell::VERBOSE);
        $org_mapping = [];
        foreach ($orgs as $org) {
            if (!empty($this->param('org')) && $org['Organisation']['name'] !== $this->param('org')) {
                continue;
            }
            if ($org['Organisation']['name'] === 'YT') {
                continue;
            }
            if ($org['Organisation']['name'] === 'ORGNAME') {
                continue;
            }
            $org_mapping[$org['Organisation']['name']] = $org['Organisation']['id'];
        }
        $time_range = [];
        if (!empty($this->param('from'))) {
            $time_range[] = $this->param('from');
        }
        if (!empty($this->param('to'))) {
            if (empty($time_range)) {
                $time_range[] = '365d';
            }
            $time_range[] = $this->param('to');
        } else {
            if (!empty($time_range)) {
                $time_range[] = '0h';
            }
        }
        $event_extended_uuids = [];
        $event_uuid_per_org = [];
        foreach ($org_mapping as $org_name => $org_id) {
            $params = [
                'org' => $org_id,
                'includeWarninglistHits' => true,
                // 'includeAnalystData' => true,
            ];
            if (!empty($time_range)) {
                $params['publish_timestamp'] = $time_range;
            }
            $response = $HttpSocket->post($server['Server']['url'] . '/events/restSearch', json_encode($params), $request);
            $events = json_decode($response->body(), true);
            $this->out(__('Events fetched from %s. %d found.', $org_name, count($events['response'])), 1, Shell::VERBOSE);
            $results[$org_name] = [
                'attribute_count' => 0,
                'object_count' => 0,
                'event_count' => count($events['response']),
                'connected_elements' => 0,
                'event_tags' => 0,
                'attribute_tags' => 0,
                'attack' => 0,
                'other' => 0,
                'attribute_attack' => 0,
                'attribute_other' => 0,
                'score' => 0,
                'warnings' => 0,
                'events_extended' => 0,
                'extending_events' => 0,
                'mitigation_detection_rules_count' => 0,
                'analyst_data_count' => 0,
            ];
            foreach ($events['response'] as $event) {
                $event_uuid_per_org[$event['Event']['uuid']] = $event['Event']['Orgc']['name'];
                if (!empty($event['Event']['extends_uuid'])) {
                    $event_extended_uuids[$event['Event']['Orgc']['name']][] = $event['Event']['extends_uuid'];
                }

                if (!empty($event['Event']['Tag'])) {
                    foreach ($event['Event']['Tag'] as $tag) {
                        if (substr($tag['name'], 0, 32) === 'misp-galaxy:mitre-attack-pattern') {
                            $results[$org_name]['attack'] += 1;
                        } else {
                            $results[$org_name]['other'] += 1;
                        }
                    }
                }
                if (!empty($event['Event']['Galaxy'])) {
                    foreach ($event['Event']['Galaxy'] as $galaxy) {
                        if ($galaxy['type'] === 'mitre-attack-pattern') {
                            $results[$org_name]['attack'] += 1;
                        } else {
                            $results[$org_name]['other'] += 1;
                        }
                    }
                }

                #  ['Note' => 0, 'Opinion' => 0, 'Relationship' => 0,]
                $analystDataCount = $this->countAnalystData($event['Event'], $org_name);
                $results[$org_name]['analyst_data_count'] = $analystDataCount['Note'] + $analystDataCount['Opinion'] + $analystDataCount['Relationship'];

                foreach ($event['Event']['Attribute'] as $attribute) {
                    if (!empty($attribute['referenced_by'])) {
                        $results[$org_name]['connected_elements'] +=1;
                    }
                    if (!empty($attribute['Tag'])) {
                        foreach ($attribute['Tag'] as $tag) {
                            if (substr($tag['name'], 0, 32) === 'misp-galaxy:mitre-attack-pattern') {
                                $results[$org_name]['attribute_attack'] += 1;
                            } else {
                                $results[$org_name]['attribute_other'] += 1;
                            }
                        }
                    }
                    if (!empty($attribute['warnings'])) {
                        $results[$org_name]['warnings'] += 1;
                    }
                }
                $results[$org_name]['attribute_count'] += count($event['Event']['Attribute']);
                if (!empty($event['Event']['Object'])) {
                    foreach ($event['Event']['Object'] as $object) {
                        $results[$org_name]['attribute_count'] += count($object['Attribute']);
                        $results[$org_name]['object_count'] += 1;
                        if (in_array($object['template_uuid'], $MITIGATION_DETECTION_OBJECT_UUIDs)) {
                            $results[$org_name]['mitigation_detection_rules_count'] += 1;
                        }
                        if (!empty($object['ObjectReference'])) {
                            $results[$org_name]['connected_elements'] += 1;
                        }
                        foreach ($object['Attribute'] as $attribute) {
                            if (!empty($attribute['Tag'])) {
                                foreach ($attribute['Tag'] as $tag) {
                                    if (substr($tag['name'], 0, 32) === 'misp-galaxy:mitre-attack-pattern') {
                                        $results[$org_name]['attribute_attack'] += 1;
                                    } else {
                                        $results[$org_name]['attribute_other'] += 1;
                                    }
                                }
                            }
                        }
                        if (!empty($attribute['warnings'])) {
                            $results[$org_name]['warnings'] += 1;
                        }
                    }
                }

            }
        }

        foreach ($event_extended_uuids as $orgc => $uuids) {
            foreach ($uuids as $uuid) {
                if (!empty($event_uuid_per_org[$uuid])) {
                    $org_name =  $event_uuid_per_org[$uuid];
                    if ($orgc != $org_name) {
                        // Add point for org extending another event
                        $results[$orgc]['extending_events'] += 1;
                        // Add point for org getting their event extended
                        $results[$org_name]['events_extended'] += 1;
                    }
                }
            }
        }


        $scores = [];
        foreach ($results as $k => $result) {
            $totalCount = $result['attribute_count'] + $result['object_count'];
            if ($totalCount) {
                if (empty($result['warnings'])) {
                    $results[$k]['metrics']['warnings'] = 100;
                } else if (100 * $result['warnings'] < $result['attribute_count']) {
                    $results[$k]['metrics']['warnings'] = 50;
                } else {
                    $results[$k]['metrics']['warnings'] = 0;
                }
                $results[$k]['metrics']['mitigation_detection_rules'] = 100 * ($result['mitigation_detection_rules_count'] / ($result['event_count']));
                $results[$k]['metrics']['connectedness'] = 100 * ($result['connected_elements'] / ($result['attribute_count'] + $result['object_count']));
                $results[$k]['metrics']['attack_weight'] = 100 * (2*($result['attack']) + $result['attribute_attack']) / ($result['attribute_count'] + $result['object_count']);
                $results[$k]['metrics']['other_weight'] = 100 * (2*($result['other']) + $result['attribute_other']) / ($result['attribute_count'] + $result['object_count']);
                // $results[$k]['metrics']['collaboration'] = 100 * ((2*$result['events_extended'] + $result['extending_events']) / $result['event_count']);
                // $results[$k]['metrics']['collaboration'] = 100 * (2*(2*$result['events_extended'] + $result['extending_events']) / $result['event_count']);
                $results[$k]['metrics']['collaboration'] = 100 * (($result['events_extended'] + $result['extending_events']));
                
                # Math magic to give lots of points of you extend or have your events extended. You quickly get point, but it slows down very quick
                if (($result['events_extended'] + $result['extending_events']) == 0) {
                    $results[$k]['metrics']['collaboration'] = 0;
                } else {
                    $results[$k]['metrics']['collaboration'] = min(5*log(($result['events_extended'] + $result['extending_events']), 1.17), 100);
                }

                $results[$k]['metrics']['collaboration_analyst'] = $result['analyst_data_count'] > 0 ? 100 : 0;
            }
            foreach (['connectedness',  'mitigation_detection_rules', 'attack_weight', 'other_weight', 'warnings', 'collaboration', 'collaboration_analyst'] as $metric) {
                if (empty($results[$k]['metrics'][$metric])) {
                    $results[$k]['metrics'][$metric] = 0;
                }
                if ($results[$k]['metrics'][$metric] > 100) {
                    $results[$k]['metrics'][$metric] = 100;
                }
            }
            $results[$k]['score'] = round(
                    15 * $results[$k]['metrics']['warnings'] +
                    15 * $results[$k]['metrics']['mitigation_detection_rules'] +
                    10 * $results[$k]['metrics']['connectedness'] +
                    40 * $results[$k]['metrics']['attack_weight'] +
                    10 * $results[$k]['metrics']['other_weight'] +
                    // 7 * $results[$k]['metrics']['collaboration'] + 3 * $results[$k]['metrics']['collaboration_analyst']
                    10 * $results[$k]['metrics']['collaboration']
                ) / 100;
            $scores[$k]['total'] = $results[$k]['score'];
            $scores[$k]['warnings'] = round(15 * $results[$k]['metrics']['warnings']);
            $scores[$k]['mitigation_detection_rules'] = round(15 * $results[$k]['metrics']['mitigation_detection_rules']);
            $scores[$k]['connectedness'] = round(10 * $results[$k]['metrics']['connectedness']);
            $scores[$k]['attack_weight'] = round(40 * $results[$k]['metrics']['attack_weight']);
            $scores[$k]['other_weight'] = round(10 * $results[$k]['metrics']['other_weight']);
            $scores[$k]['collaboration'] = round(7 * $results[$k]['metrics']['collaboration']) + round(3 * $results[$k]['metrics']['collaboration_analyst']);
        }
        arsort($scores, SORT_DESC);
        $this->out(str_repeat('=', 128), 1, Shell::NORMAL);
        $this->out(sprintf(
            '| %s | %s | %s |',
            str_pad('Org', 10, ' ', STR_PAD_RIGHT),
            str_pad('Graph', 100, ' ', STR_PAD_RIGHT),
            str_pad('Score', 8, ' ', STR_PAD_RIGHT)
        ), 1, Shell::NORMAL);
        $this->out(str_repeat('=', 128), 1, Shell::NORMAL);
        foreach ($scores as $org => $score) {
            $score_string[0] = str_repeat('█', round($score['warnings']/100));
            $score_string[1] = str_repeat('█', round($score['mitigation_detection_rules']/100));
            $score_string[2] = str_repeat('█', round($score['connectedness']/100));
            $score_string[3] = str_repeat('█', round($score['attack_weight']/100));
            $score_string[4] = str_repeat('█', round($score['other_weight']/100));
            $score_string[5] = str_repeat('█', round($score['collaboration']/100));
            $this->out(sprintf(
                '| %s | %s | %s |',
                str_pad($org, 10, ' ', STR_PAD_RIGHT),
                sprintf(
                    '<error>%s</error><black>%s</black><warning>%s</warning><question>%s</question><info>%s</info><green>%s</green>%s',
                    $score_string[0],
                    $score_string[1],
                    $score_string[2],
                    $score_string[3],
                    $score_string[4],
                    $score_string[5],
                    str_repeat(' ', 100 - mb_strlen(implode('', $score_string)))
                ),
                str_pad($score['total'] . '%', 8, ' ', STR_PAD_RIGHT)
            ), 1, Shell::NORMAL);
        }
        $this->out(str_repeat('=', 128), 1, Shell::NORMAL);
        $this->out(sprintf(
            '| Legend: %s %s %s %s %s %s |',
            '<error>█: Warnings</error>',
            '<black>█: Detection/Mitigation Rules</black>',
            '<warning>█: Connectedness</warning>',
            '<question>█: ATT&CK context</question>',
            '<info>█: Other Context</info>',
            '<green>█: Collaboration</green>',
            str_repeat(' ', 52)
        ), 1, Shell::NORMAL);
        $this->out(str_repeat('=', 128), 1, Shell::NORMAL);
        file_put_contents(APP . 'tmp/report.json', json_encode($results, JSON_PRETTY_PRINT));
    }

    private function countAnalystData($data, $orgc_name): array {
        $analystTypes = ['Note', 'Opinion', 'Relationship'];
        $counts = [
            'Note' => 0,
            'Opinion' => 0,
            'Relationship' => 0,
        ];

        foreach ($analystTypes as $type) {
            if (!empty($data[$type])) {
                foreach ($data[$type] as $entry) {
                    if ($entry['Orgc']['name'] == $orgc_name) {
                        $counts[$type] += 1;
                    }
                }
                foreach ($data[$type] as $child) {
                    $nestedCounts = $this->countAnalystData($child, $orgc_name);
                    $counts['Note'] += $nestedCounts['Note'];
                    $counts['Opinion'] += $nestedCounts['Opinion'];
                    $counts['Relationship'] += $nestedCounts['Relationship'];
                }
            }
        }
        return $counts;
    }
}
