<?php

/**
 * MISP Workers — background-queue health widget.
 *
 * Renders one row per queue (DD-38, `QueueList` render kind):
 *
 *     [glyph] queue_name     [alive/total]  [pending_jobs]
 *
 * The two right-aligned chips are independently coloured:
 *
 *   workers — `0/0` warning (no workers configured for this queue),
 *             `x < y` danger (some workers down), `x == y` info (healthy).
 *
 *   jobs    — `< 50` info, `50..99` warning, `>= 100` danger
 *             (queue is piling up). The scheduler queue has no jobCount
 *             and renders without a jobs chip.
 *
 * A piling-up queue (jobs chip warning/danger) sitting next to a healthy
 * workers chip is the at-a-glance signal for "workers are alive but
 * stuck" — the rework's primary motivation.
 *
 * Site-admin only. Render kind QueueList (theme-independent token chrome
 * + per-queue inline-SVG glyph via QueueGlyph).
 */
class MispAdminWorkerWidget
{
    public $title = 'MISP Workers';
    public $category = 'system';
    public $render = 'QueueList';
    public $width = 3;
    public $height = 4;
    public $params = array();
    public $schema = array();
    public $description = 'Background-queue health: alive workers and pending jobs per queue.';
    public $cacheLifetime = false;
    // Worker health is the "is the box healthy right now" signal, so the
    // value of this widget is freshness. Cache disabled; the diagnostics
    // call is cheap (a supervisor poll + 5 Redis LLENs).
    public $autoRefreshDelay = 5;

    public function handler($user, $options = array())
    {
        App::uses('BackgroundJobsTool', 'Tools');
        $this->Server = ClassRegistry::init('Server');
        // workerDiagnostics() takes the issue counter by reference and
        // does $workerIssueCount++ internally. It must be an int — the
        // array() init (the original 2020 v1 value) is a silent no-op
        // under PHP 7 but throws "Cannot increment array" on PHP 8.x.
        // Every other caller (AdminShell, ServersController) passes 0.
        $workerIssueCount = 0;
        $results = $this->Server->workerDiagnostics($workerIssueCount);

        $rows = array();
        $queueCount = 0;
        $aliveSum = 0;
        // workerDiagnostics() mixes per-queue arrays with top-level
        // scalar/bool summary keys (`controls`, `proc_accessible`,
        // `supervisord_status`); constrain to the real queue list
        // instead of skipping by name so any future top-level key the
        // function adds doesn't accidentally render as a "queue".
        $validQueues = BackgroundJobsTool::VALID_QUEUES;
        foreach ($validQueues as $queueName) {
            if (!isset($results[$queueName]) || !is_array($results[$queueName])) {
                continue;
            }
            $queue = $results[$queueName];
            $alive = 0;
            $total = 0;
            if (!empty($queue['workers'])) {
                foreach ($queue['workers'] as $worker) {
                    if (!empty($worker['alive'])) {
                        $alive++;
                    }
                    $total++;
                }
            }

            // Workers colour: `0/0` warning, `x < y` danger, `x == y` info.
            // The `0/0` rule takes precedence over `x == y` (both true when
            // the queue has no workers configured at all).
            if ($total === 0) {
                $workersClass = 'warning';
            } elseif ($alive < $total) {
                $workersClass = 'danger';
            } else {
                $workersClass = 'info';
            }

            $row = array(
                'type'  => 'queue',
                'queue' => $queueName,
                'name'  => $queueName,
                'glyph' => $queueName,
                'alive' => $alive,
                'total' => $total,
                'workers_class' => $workersClass,
                'drilldown' => '/servers/serverSettings/workers',
            );

            // The scheduler queue has no jobCount (it dispatches, doesn't
            // ingest). Other queues get a jobs chip even at 0 so a healthy
            // empty queue still shows the info pill.
            if (array_key_exists('jobCount', $queue)) {
                $jobs = (int)$queue['jobCount'];
                if ($jobs >= 100) {
                    $jobsClass = 'danger';
                } elseif ($jobs >= 50) {
                    $jobsClass = 'warning';
                } else {
                    $jobsClass = 'info';
                }
                $row['jobs'] = $jobs;
                $row['jobs_class'] = $jobsClass;
            }

            $rows[] = $row;
            $queueCount++;
            $aliveSum += $alive;
        }

        $header = array(
            'type'  => 'header',
            'value' => sprintf(
                '%d %s · %d %s',
                $queueCount,
                ($queueCount === 1 ? __('queue') : __('queues')),
                $aliveSum,
                ($aliveSum === 1 ? __('worker alive') : __('workers alive'))
            ),
        );

        array_unshift($rows, $header);
        return $rows;
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
