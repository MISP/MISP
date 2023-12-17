<?php

namespace App\Model\Table;

use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\ProcessTool;
use App\Model\Table\AppTable;
use Cake\Core\Configure;
use Exception;

class ServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('EncryptedFields', ['fields' => ['authkey']]);
    }

    public function captureServer($server, $user)
    {
        if (isset($server[0])) {
            $server = $server[0];
        }
        if ($server['url'] == Configure::read('MISP.baseurl')) {
            return 0;
        }
        $existingServer = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['url' => $server['url']]
            ]
        )->disableHydration()->first();
        // unlike with other capture methods, if we find a server that we don't know
        // we don't want to save it.
        if (empty($existingServer)) {
            return false;
        }
        return $existingServer['id'];
    }

    public function fetchServer($id)
    {
        if (empty($id)) {
            return false;
        }
        $conditions = ['Servers.id' => $id];
        if (!is_numeric($id)) {
            $conditions = ['OR' => [
                'LOWER(Servers.name)' => strtolower($id),
                'LOWER(Servers.url)' => strtolower($id)
            ]
            ];
        }
        $server = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1
            ]
        )->disableHydration()->first();
        return (empty($server)) ? false : $server;
    }

    /**
     * @param int $workerIssueCount
     * @return array
     * @throws ProcessException
     */
    public function workerDiagnostics(&$workerIssueCount)
    {
        $worker_array = [
            'cache' => ['ok' => false],
            'default' => ['ok' => false],
            'email' => ['ok' => false],
            'prio' => ['ok' => false],
            'update' => ['ok' => false]
        ];

        try {
            $workers = $this->getWorkers();
        } catch (Exception $e) {
            // TODO: [3.x-MIGRATION] check exception logging in 3.x
            // $this->logException('Could not get list of workers.', $e);
            return $worker_array;
        }

        $currentUser = ProcessTool::whoami();
        $procAccessible = file_exists('/proc');
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                throw new Exception('Non numeric PID found.');
            }
            $entry = $worker['type'] === 'regular' ? $worker['queue'] : $worker['type'];
            $correctUser = ($currentUser === $worker['user']);
            if ($procAccessible) {
                $alive = $correctUser && file_exists("/proc/$pid");
            } else {
                $alive = 'N/A';
            }
            $ok = true;
            if (!$alive || !$correctUser) {
                $ok = false;
                $workerIssueCount++;
            }
            $worker_array[$entry]['workers'][] = [
                'pid' => $pid,
                'user' => $worker['user'],
                'alive' => $alive,
                'correct_user' => $correctUser,
                'ok' => $ok
            ];
        }
        foreach ($worker_array as $k => $queue) {
            if (isset($queue['workers'])) {
                foreach ($queue['workers'] as $worker) {
                    if ($worker['ok']) {
                        $worker_array[$k]['ok'] = true; // If at least one worker is up, the queue can be considered working
                    }
                }
            }

            $worker_array[$k]['jobCount'] = BackgroundJobsTool::getInstance()->getQueueSize($k);

            if (!isset($queue['workers'])) {
                $workerIssueCount++;
                $worker_array[$k]['ok'] = false;
            }
        }
        $worker_array['proc_accessible'] = $procAccessible;
        $worker_array['controls'] = 1;
        if (Configure::check('MISP.manage_workers')) {
            $worker_array['controls'] = Configure::read('MISP.manage_workers');
        }

        if (Configure::read('BackgroundJobs.enabled')) {
            try {
                $worker_array['supervisord_status'] = BackgroundJobsTool::getInstance()->getSupervisorStatus();
            } catch (Exception $exception) {
                $this->logException('Error getting supervisor status.', $exception);
                $worker_array['supervisord_status'] = false;
            }
        }

        return $worker_array;
    }
}
