<?php
// Overmind BS5 index for scheduled tasks. Mirrors the legacy Default index
// (columns + the per-row force-run / view-logs / enable-disable / edit / delete
// actions), rendered through the BS5 scaffold. The whole controller is
// site-admin only (index() throws otherwise), so no per-action ACL gating is
// needed here. There is no search box because index() builds no search params.
$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$schedulerEnabled = $this->viewVars['schedulerEnabled'] ?? false;

$headerActions = [
    [
        'type' => 'modal',
        'label' => __('Add scheduled task'),
        'icon' => 'plus',
        'url' => $baseurl . '/tasks/add',
    ],
];
$this->set('headerTitle', __('Scheduled Tasks'));
$this->set('headerDescription', __('Pre-defined tasks (Server pull/push/cache, Feed fetch/cache, Workflow, TAXII push, periodic summary or admin update) executed in the background every X seconds/minutes/hours/days.'));
$this->set('headerActions', $headerActions);

$fields = [
    [
        'name' => __('ID'),
        'sort' => 'Task.id',
        'data_path' => 'Task.id',
        'element' => 'id',
        'url' => '#',
    ],
    [
        'name' => __('Type'),
        'sort' => 'Task.type',
        'data_path' => 'Task.type',
    ],
    [
        'name' => __('Action'),
        'sort' => 'Task.action',
        'data_path' => 'Task.action',
    ],
    [
        'name' => __('Parameters'),
        'sort' => 'Task.params',
        'data_path' => 'Task.params',
    ],
    [
        'name' => __('Description'),
        'sort' => 'Task.description',
        'data_path' => 'Task.description',
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'element' => 'custom',
        'function' => function (array $row) use ($baseurl) {
            if (empty($row['User']['email'])) {
                return '<span class="text-muted">-</span>';
            }
            return sprintf(
                '<a href="%s/users/view/%s">%s</a>',
                h($baseurl),
                h($row['User']['id']),
                h($row['User']['email'])
            );
        },
    ],
    [
        'name' => __('Frequency'),
        'sort' => 'Task.timer',
        'data_path' => 'Task.timer',
        'element' => 'custom',
        'function' => function (array $row) {
            $seconds = (int)$row['Task']['timer'];
            if ($seconds <= 0) {
                return h(__('invalid interval'));
            }
            $units = [
                86400 => 'day',
                3600  => 'hour',
                60    => 'minute',
                1     => 'second',
            ];
            $parts = [];
            foreach ($units as $unitSeconds => $unitName) {
                if ($seconds >= $unitSeconds) {
                    $value = intdiv($seconds, $unitSeconds);
                    $seconds %= $unitSeconds;
                    $parts[] = $value . ' ' . $unitName . ($value > 1 ? 's' : '');
                }
            }
            return h('every ' . implode(' ', $parts));
        },
    ],
    [
        'name' => __('Last run at'),
        'sort' => 'Task.last_run_at',
        'data_path' => 'Task.last_run_at',
        'element' => 'datetime',
    ],
    [
        'name' => __('Next execution'),
        'sort' => 'Task.next_execution_time',
        'data_path' => 'Task.next_execution_time',
        'element' => 'datetime',
    ],
    [
        'name' => __('Status'),
        'sort' => 'Task.message',
        'data_path' => 'Task.message',
    ],
    [
        'name' => __('Last Job status'),
        'element' => 'custom',
        'function' => function (array $row) {
            // A task with no last_job_id still comes back with a null-filled Job
            // array (belongsTo left-join), so gate on the real Job id.
            if (empty($row['Job']['id'])) {
                return '<span class="text-muted">' . h(__('No job executed yet')) . '</span>';
            }
            $status = $row['Job']['status'];
            switch ($status) {
                case Job::STATUS_COMPLETED:
                    return '<span class="badge text-bg-success">' . h(__('Completed')) . '</span>';
                case Job::STATUS_FAILED:
                    return '<span class="badge text-bg-danger">' . h(__('Failed')) . '</span>';
                case Job::STATUS_RUNNING:
                    return '<span class="badge text-bg-info">' . h(__('Running')) . '</span>';
                default:
                    return '<span class="badge text-bg-secondary">' . h(__('Unknown')) . '</span>';
            }
        },
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Task.enabled',
        'data_path' => 'Task.enabled',
        'element' => 'enabled',
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Task.id',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Force run'),
                'icon' => 'play',
                'url' => $baseurl . '/tasks/forceRun/%id%',
                'requirement' => function ($row) {
                    return !empty($row['Task']['enabled']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('View logs'),
                'icon' => 'file-lines',
                'url' => $baseurl . '/tasks/viewLogs/%id%',
                'requirement' => function ($row) {
                    return !empty($row['Job']['id']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Enable'),
                'icon' => 'toggle-on',
                'url' => $baseurl . '/tasks/toggleEnabled/%id%',
                'requirement' => function ($row) {
                    return empty($row['Task']['enabled']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Disable'),
                'icon' => 'toggle-off',
                'url' => $baseurl . '/tasks/toggleEnabled/%id%',
                'requirement' => function ($row) {
                    return !empty($row['Task']['enabled']);
                },
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/tasks/edit/%id%',
            ],
            [
                'type' => 'postLink',
                'label' => __('Delete'),
                'icon' => 'trash',
                'url' => $baseurl . '/tasks/delete/%id%',
                'class' => 'text-danger',
                'confirm' => __('Are you sure you want to delete this scheduled task?'),
            ],
        ],
    ],
];

if (!$schedulerEnabled) {
    echo '<div class="container-fluid"><div class="alert alert-danger" role="alert">';
    echo __('The task scheduler is not enabled. To enable it please add the missing %s program configuration to your supervisor configuration file (%s).', '<code>scheduler</code>', '<code>/etc/supervisor/conf.d/*-workers.conf</code>');
    echo '<br>';
    echo __('You can find the sample configuration file in %s.', '<code>build/supervisor/50-workers.conf</code>');
    echo '<br>';
    echo __('For more information, please refer to the %s.', '<a href="https://github.com/MISP/MISP/wiki/Supervisor-Task-Scheduler-Guide-(2.5)">' . __('MISP documentation') . '</a>');
    echo '</div></div>';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Task.id',
            'fields' => $fields,
        ],
    ],
    'item_url' => '/tasks',
]);
