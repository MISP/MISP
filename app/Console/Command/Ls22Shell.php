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
                        'authkey' => trim($fields[2])
                    ]
                ];
            }
        }
    }

    public function getOptionParser()
    {
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
                    ]
                ),
            ),
        ]);
        return $parser;
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
            $response = $HttpSocket->get($server['Server']['url'] . '/users/view/me', false, $request);
            $execution_time = round((microtime(true) - $start_time) * 1000);
            $statusWrapped = sprintf(
                '<%s>%s</%s>',
                $response->isOk() ? 'info' : 'error',
                $response->isOk() ? 'OK (' . $execution_time . 'ms)' : 'Failed. (' . $response->code . ')',
                $response->isOk() ? 'info' : 'error'
            );
            $this->out($server['Server']['url'] . ': ' . $statusWrapped, 1, Shell::NORMAL);
            $results[$server['Server']['url']] = $response->isOk() ? $execution_time : false;
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

    public function scores()
    {
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
        $response = $HttpSocket->get($server['Server']['url'] . '/organisations/index', false, $request);
        $orgs = json_decode($response->body(), true);
        $this->out(__('Organisations fetched. %d found.', count($orgs)), 1, Shell::VERBOSE);
        $org_mapping = [];
        foreach ($orgs as $org) {
            $name = explode(' ', $org['Organisation']['name']);
            if ($name[0] !== 'BT') {
                continue;
            }
            $org_mapping[$org['Organisation']['name']] = $org['Organisation']['id'];
        }
        foreach ($org_mapping as $org_name => $org_id) {
            $time_range = [];
            if (!empty($this->param['from'])) {
                $time_range[] = $this->param['from'];
            }
            if (!empty($this->param['to'])) {
                if (empty($time_range)) {
                    $time_range[] = '365d';
                }
                $time_range[] = $this->param['to'];
            }
            $params = [
                'org' => $org_id
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
                'connected_elements' => 0,
                'event_tags' => 0,
                'attribute_tags' => 0,
                'attack' => 0,
                'other' => 0,
                'attribute_attack' => 0,
                'attribute_other' => 0,
                'score' => 0
            ];
            foreach ($events['response'] as $event) {
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
                }
                $results[$org_name]['attribute_count'] += count($event['Event']['Attribute']);
                if (!empty($event['Event']['Object'])) {
                    foreach ($event['Event']['Object'] as $object) {
                        $results[$org_name]['attribute_count'] += count($object['Attribute']);
                        $results[$org_name]['object_count'] += 1;
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
                    }
                }

            }
        }
        $scores = [];
        foreach ($results as $k => $result) {
            $totalCount = $result['attribute_count'] + $result['object_count'];
            if ($totalCount) {
                $results[$k]['metrics']['connectedness'] = 100 * ($result['connected_elements'] / ($result['attribute_count'] + $result['object_count']));
                $results[$k]['metrics']['attack_weight'] = 100 * (2*($result['attack']) + $result['attribute_attack']) / ($result['attribute_count'] + $result['object_count']);
                $results[$k]['metrics']['other_weight'] = 100 * (2*($result['other']) + $result['attribute_other']) / ($result['attribute_count'] + $result['object_count']);
            }
            foreach (['connectedness', 'attack_weight', 'other_weight'] as $metric) {
                if (empty($results[$k]['metrics'][$metric])) {
                    $results[$k]['metrics'][$metric] = 0;
                }
                if ($results[$k]['metrics'][$metric] > 100) {
                    $results[$k]['metrics'][$metric] = 100;
                }
            }
            $results[$k]['score'] = round(40 * $results[$k]['metrics']['connectedness'] + 40 * $results[$k]['metrics']['attack_weight'] + 20 * $results[$k]['metrics']['other_weight']) / 100;
            $scores[$k] = $results[$k]['score'];
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
            $score_string = str_repeat('█', round($score));
            $this->out(sprintf(
                '| %s | %s | %s |',
                str_pad($org, 10, ' ', STR_PAD_RIGHT),
                sprintf(
                    '<info>%s</info>%s',
                    $score_string,
                    str_repeat(' ', 100 - mb_strlen($score_string))
                ),
                str_pad($score . '%', 8, ' ', STR_PAD_RIGHT)
            ), 1, Shell::NORMAL);
        }
        $this->out(str_repeat('=', 128), 1, Shell::NORMAL);
    }
}
