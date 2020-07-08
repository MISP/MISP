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
}
