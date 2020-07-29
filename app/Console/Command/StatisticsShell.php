<?php
class StatisticsShell extends AppShell {

    public function contributors()
    {
        $from = empty($this->args[0]) ? null : $this->args[0];
        $to = empty($this->args[1]) ? null : $this->args[1];
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
        $emails = $this->User->find('list', [
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
                "%s | %s\n",
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
}
