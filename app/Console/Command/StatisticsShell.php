<?php

App::uses('HttpSocket', 'Network/Http');

class StatisticsShell extends AppShell {

    public $uses = array('Event', 'User', 'Organisation', 'Log', 'Correlation');

    public function contributors()
    {
        $from = empty($this->args[0]) ? null : $this->args[0];
        $to = empty($this->args[1]) ? null : $this->args[1];
        $prs = $this->__getPRs($from, $to);
        echo PHP_EOL . PHP_EOL . "PRs opened: " . $prs['opened'] . PHP_EOL . "PRs merged: " . $prs['merged'] . PHP_EOL;
        $repos = [
            ROOT,
            ROOT . '/PyMISP',
            ROOT . '/app/files/misp-galaxy',
            ROOT . '/app/files/misp-objects',
            ROOT . '/app/files/noticelists',
            ROOT . '/app/files/taxonomies',
            ROOT . '/app/files/warninglists'
        ];
        $results = [];
        foreach ($repos as $repo) {
            $results = $this->extract($results, $repo, $from, $to);
        }
        echo PHP_EOL . PHP_EOL . array_sum($results) . ' commits from ' . count($results) . ' unique contributors.' . PHP_EOL . PHP_EOL;
        arsort($results);
        foreach ($results as $email => $count) {
            echo $email . ': ' . $count . PHP_EOL;
        }
    }

    private function __getPRs($from, $to)
    {
        $PRs = 0;
        $merged = 0;
        $projects = [
            'MISP/PyMISP',
            'MISP/MISP',
            'MISP/misp-objects',
            'MISP/taxonomies',
            'MISP/warninglists',
            'MISP/misp-galaxy'
        ];
        $HttpSocket = new HttpSocket();
        foreach ($projects as $project) {
            $url = sprintf(
                'https://api.github.com/search/issues?q=repo:%s+is:pr%s%s',
                $project,
                $from ? '+created:>=' . $from : '',
                $to ? '+created:<=' . $to : ''
            );
            $result = $HttpSocket->get($url);
            $result = json_decode($result, true);
            if (!empty($result['total_count'])) {
                $PRs += $result['total_count'];
            }
            $url = sprintf(
                'https://api.github.com/search/issues?q=repo:%s+is:pr+is:closed+merged:%s..%s',
                $project,
                $from ? $from : '2012-01-01',
                $to ? $to : date("Y-m-d")
            );
            $result = $HttpSocket->get($url);
            $result = json_decode($result, true);
            if (!empty($result['total_count'])) {
                $merged += $result['total_count'];
            }
        }
        return ['opened' => $PRs, 'merged' => $merged];
    }

    private function extract($results, $repo, $from, $to)
    {
        $data = shell_exec(
            sprintf(
                'git --git-dir ' . $repo . '/.git shortlog -sne %s %s',
                $from ? (sprintf('--since="%s"', $from)) : '',
                $to ? (sprintf('--since="%s"', $to)) : ''
            )
        );
        $data = explode(PHP_EOL, $data);
        foreach ($data as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
            $email = null;
            $count = null;
            preg_match('/\<.+\>/', $line, $email);
            $email = trim($email[0], '<>');
            preg_match('/^[0-9]+/', $line, $count);
            if (isset($results[$email])) {
                $results[$email] += $count[0];
            } else {
                $results[$email] = $count[0];
            }
        }
        return $results;
    }

    public function analyse_slow_logs()
    {
        $path = $this->args[0];
        $raw = file_get_contents($path);
        $raw = explode("\n", $raw);
        $data = [
            'users' => [],
            'non_sync_action_users' => [],
            'endpoints' => []
        ];
        $this->User = ClassRegistry::init('User');
        $users = $this->User->find('list', [
            'fields' => ['id', 'email']
        ]);
        foreach ($raw as $line) {
            if (empty($line)) {
                continue;
            }
            if ($line[0] === '/' && $line[1] === '*') {
                $temp = preg_match('/\/\*\s\[User\:\s([0-9]+)\]/', $line, $matches);
                if (!empty($matches[1])) {
                    $user = $matches[1];
                    if (isset($data['users'][$user])) {
                        $data['users'][$user] += 1;
                    } else {
                        $data['users'][$user] = 1;
                    }
                }
                $temp = preg_match('/\]\s([a-z\:\s]*)/', $line, $matches);
                if (!empty($matches[1])) {
                    $endpoint = $matches[1];
                    $endpoint = trim($endpoint);
                    if (isset($data['endpoints'][$endpoint])) {
                        $data['endpoints'][$endpoint] += 1;
                    } else {
                        $data['endpoints'][$endpoint] = 1;
                    }
                }
                if (!in_array($endpoint, ['events :: add', 'events :: edit', 'events :: index'])) {
                    if (isset($data['non_sync_action_users'][$user])) {
                        $data['non_sync_action_users'][$user] += 1;
                    } else {
                        $data['non_sync_action_users'][$user] = 1;
                    }
                }
            }
        }
        arsort($data['endpoints']);
        arsort($data['users']);
        arsort($data['non_sync_action_users']);
        echo "\n\n==================================\nCount | User\n";
        echo "\n\n==================================\nSlow queries by user general\n==================================\nCount | User  | Email\n";
        foreach ($data['users'] as $user_id => $count) {
            echo sprintf(
                "%s | %s | %s\n",
                str_pad($count, 5),
                str_pad($user_id, 5),
                !empty($users[$user_id]) ? $users[$user_id] : ''
            );
        }
        echo "\n\n==================================\nSlow queries by user excluding sync\n==================================\nCount | User  | Email\n";
        foreach ($data['non_sync_action_users'] as $user_id => $count) {
            echo sprintf(
                "%s | %s | %s\n",
                str_pad($count, 5),
                str_pad($user_id, 5),
                !empty($users[$user_id]) ? $users[$user_id] : ''
            );
        }
        echo "\n\n==================================\nSlow queries by endpoint\n==================================\nCount | Endpoint\n";
        foreach ($data['endpoints'] as $endpoint => $count) {
            echo sprintf(
                "%s | %s\n",
                str_pad($count, 5),
                $endpoint
            );
        }
        echo "==================================\n\n";
    }

    public function orgEngagement()
    {
        $orgs = $this->Organisation->find('list', [
            'recursive' => -1,
            'fields' => ['Organisation.id', 'Organisation.id'],
            'conditions' => ['Organisation.local' => 1]
        ]);
        $orgs = array_values($orgs);
        $total_orgs = count($orgs);
        $data = [];
        $orgCreations = $this->Log->find('list', [
            'conditions' => [
                'model' => 'Organisation',
                'action' => 'add'
            ],
            'fields' => ['Log.model_id', 'Log.created']
        ]);
        $localOrgs = $this->Organisation->find('count', [
            'conditions' => [
                'Organisation.local' => 1
            ]
        ]);
        foreach ($orgs as $k => $org) {
            echo sprintf(__('Processing organisation %s / %s.%s', $k+1, $total_orgs, PHP_EOL));
            $temp = [
                'org_id' => $org
            ];
            if (empty($orgCreations[$org])) {
                continue;
            } else {
                $temp['org_creation_timestamp'] = strtotime($orgCreations[$org]);
            }
            $first_event = $this->Event->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'orgc_id' => $org
                ],
                'order' => ['Event.id ASC'],
                'fields' => ['Event.id']
            ]);
            if (empty($first_event)) {
                continue;
            }
            $first_event_creation = $this->Log->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'model_id' => $first_event['Event']['id'],
                    'model' => 'Event',
                    'action' => 'add'
                ]
            ]);
            if (empty($first_event_creation)) {
                continue;
            }
            $temp['first_event_creation'] = strtotime($first_event_creation['Log']['created']);
            $temp['time_until_first_event'] = $temp['first_event_creation'] - $temp['org_creation_timestamp'];
            $data[] = $temp;
        }
        $average_time_to_first_event = 0;
        foreach ($data as $org_data) {
            $average_time_to_first_event += (int)$org_data['time_until_first_event'] / 60 / 60 / 24;
        }
        echo PHP_EOL . str_repeat('-', 63) . PHP_EOL;
        echo __('Total local orgs: %s%s', $localOrgs, PHP_EOL);
        echo __('Local orgs with event creations: %s%s', count($data), PHP_EOL);
        echo __('Average days until first event: %s', (int)($average_time_to_first_event / count($data)));
        echo PHP_EOL . str_repeat('-', 63) . PHP_EOL;
    }

    public function yearlyOrgGrowth()
    {
        $orgCreations = $this->Log->find('list', [
            'conditions' => [
                'model' => 'Organisation',
                'action' => 'add'
            ],
            'fields' => ['Log.model_id', 'Log.created']
        ]);
        $localOnly = empty($this->args[0]) ? false : true;
        if ($localOnly) {
            $orgs = $this->Organisation->find('list', [
                'recursive' => -1,
                'fields' => ['Organisation.id', 'Organisation.local']
            ]);
            foreach ($orgs as $org_id => $local) {
                if (!$local && isset($orgCreations[$org_id])) {
                    unset($orgCreations[$org_id]);
                }
            }
        }
        $years = [];
        foreach ($orgCreations as $orgCreation) {
            $year = substr($orgCreation, 0, 4);
            if (empty($years[$year])) {
                $years[$year] = 0;
            }
            $years[$year] += 1;
        }
        ksort($years);
        $yearOverYear = [];
        $previous = 0;
        echo PHP_EOL . str_repeat('-', 63) . PHP_EOL;
        echo __('Year over year growth of organisation count.');
        echo PHP_EOL . str_repeat('-', 63) . PHP_EOL;
        $currentYear = date("Y");
        foreach ($years as $year => $count) {
            $prognosis = '';
            if ($year == $currentYear) {
                $percentage_passed = (strtotime(($year +1) . '-01-01') - strtotime(($year) . '-01-01')) / (time() - (strtotime($year . '-01-01')));
                $prognosis = sprintf(' (%s by the end of the year at current rate)', round($percentage_passed * $count));
            }
            echo __('%s: %s %s%s', $year, $count - $previous, $prognosis, PHP_EOL);
        }
        echo str_repeat('-', 63) . PHP_EOL;
    }

    // (R)etrieval (o)f (m)ember (m)etrics (e)valuation (l)ist (f)or (s)tatistics
    public function rommelfs()
    {
        $this->out(json_encode([
            'events' => $this->Event->find('count'),
            'attributes' => $this->Event->Attribute->find('count',
                ['recursive' => -1]
            ),
            'objects' => $this->Event->Object->find('count',
                ['recursive' => -1]
            ),
            'correlations' => $this->Correlation->find('count') / 2,
            'users' => $this->User->find('count',
                ['conditions' => ['User.disabled' => 0], 'recursive' => -1]
            ),
            'local_organisations' => $this->Organisation->find('count',
                ['conditions' => ['Organisation.local' => 1], 'recursive' => -1]
            ),
            'external_organisations' => $this->Organisation->find('count',
                ['conditions' => ['Organisation.local' => 0], 'recursive' => -1]
            )
        ], JSON_PRETTY_PRINT));
    }
}
