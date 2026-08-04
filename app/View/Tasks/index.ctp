<?php
echo sprintf('<div%s>', empty($ajax) ? ' class="index"' : '');

if (!$schedulerEnabled) {
    echo '<div class="alert alert-danger">';
    echo __('The task scheduler is not enabled. To enable it please add the missing <code>scheduler</code> program configuration to your supervisor configuration file (%s).', '<code>/etc/supervisor/conf.d/*-workers.conf</code>');
    echo '<br>';
    echo __('You can find the sample configuration file in %s.', '<code>build/supervisor/50-workers.conf</code>');
    echo '<br>';
    echo __('For more information, please refer to the %s.', '<a href="https://github.com/MISP/MISP/wiki/Supervisor-Task-Scheduler-Guide-(2.5)">MISP documentation</a>');
    echo '</div>';
}
$fields = [
    [
        'name' => '#',
        'sort' => 'Task.id',
        'data_path' => 'Task.id',
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
        'element' => 'links',
        'url' => $baseurl . '/users/view',
        'url_params_data_paths' => ['User.id'],
        'sort' => 'User.email   ',
        'data_path' => 'User.email',
    ],
    [
        'name' => __('Frequency'),
        'sort' => 'Task.timer',
        'data_path' => 'Task.timer',
        'element' => 'custom',
        'function' => function (array $row) {
            $seconds = $row['Task']['timer'];

            if ($seconds <= 0) return "invalid interval";

            $units = [
                86400 => 'day',
                3600  => 'hour',
                60    => 'minute',
                1     => 'second'
            ];

            $parts = [];

            foreach ($units as $unitSeconds => $unitName) {
                if ($seconds >= $unitSeconds) {
                    $value = intdiv($seconds, $unitSeconds);
                    $seconds %= $unitSeconds;
                    $parts[] = "$value $unitName" . ($value > 1 ? 's' : '');
                }
            }

            return h('every ' . implode(' ', $parts));
        }
    ],
    [
        'name' => __('Last run at'),
        'sort' => 'Task.last_run_at',
        'element' => 'datetime',
        'data_path' => 'Task.last_run_at',
    ],
    [
        'name' => __('Next execution'),
        'sort' => 'Task.next_execution_time',
        'element' => 'datetime',
        'data_path' => 'Task.next_execution_time',
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
            if (empty($row['Job'])) {
                return __('No job executed yet');
            }

            $status = $row['Job']['status'];
            switch ($status) {
                case Job::STATUS_COMPLETED:
                    return '<span class="badge badge-success">' . __('Completed') . '</span>';
                case Job::STATUS_FAILED:
                    return '<span class="badge badge-danger">' . __('Failed') . '</span>';
                case Job::STATUS_RUNNING:
                    return '<span class="badge badge-info">' . __('Running') . '</span>';
                default:
                    return '<span class="badge badge-secondary">' . __('Unknown') . '</span>';
            }
        }
    ],
    [
        'name' => __('Enabled'),
        'element' => 'toggle',
        'url' => $baseurl . '/tasks/toggleEnabled',
        'url_params_data_paths' => array(
            'Task.id'
        ),
        'sort' => 'required',
        'class' => 'short',
        'data_path' => 'Task.enabled',
        'disabled' => !$isSiteAdmin,
    ],
];
echo $this->element('genericElements/IndexTable/index_table', [
    'data' => [
        'data' => $data,
        'top_bar' => [
            'pull' => 'right',
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        'data' => [
                            'type' => 'simple',
                            'fa-icon' => 'plus',
                            'text' => __('Add scheduled task'),
                            'class' => 'btn-primary modal-open',
                            'url' => "$baseurl/tasks/add",
                        ]
                    ]
                ]
            ]
        ],
        'fields' => $fields,
        'title' => empty($ajax) ? __('Scheduled Tasks Index') : false,
        'description' => empty($ajax) ? __('Here you can schedule pre-defined tasks that will be executed every X seconds/minutes/hours/days.') : false,
        'pull' => 'right',
        'actions' => [
            [
                'class' => 'modal-open',
                'url' => "$baseurl/tasks/forceRun",
                'url_params_data_paths' => ['Task.id'],
                'icon' => 'play',
                'title' => __('Force run task'),
                'complex_requirement' => function ($task) {
                    return $task['Task']['enabled'];
                },
            ],
            [
                'class' => 'modal-open',
                'url' => "$baseurl/tasks/viewLogs",
                'url_params_data_paths' => ['Task.id'],
                'icon' => 'file-alt',
                'title' => __('View task logs'),
            ],
            [
                'url' => $baseurl . '/tasks/edit',
                'url_params_data_paths' => array(
                    'Task.id'
                ),
                'icon' => 'edit',
                'title' => 'Edit task',
            ],
            [
                'class' => 'modal-open',
                'url' => "$baseurl/tasks/delete",
                'url_params_data_paths' => ['Task.id'],
                'icon' => 'trash',
                'title' => __('Delete task'),
            ]
        ]
    ]
]);
echo '</div>';
if (empty($ajax)) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'tasks'));
}
