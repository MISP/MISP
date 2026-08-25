<?php
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

// Human-friendly interval string ("every 5 minutes") from a seconds count.
$formatFrequency = function ($seconds) {
    $seconds = (int)$seconds;
    if ($seconds <= 0) {
        return null;
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
    return 'every ' . implode(' ', $parts);
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Task.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Task.id',
        'data_path' => 'Task.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Type'),
        'sort' => 'Task.type',
        'data_path' => 'Task.type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Action'),
        'sort' => 'Task.action',
        'data_path' => 'Task.action',
        'element' => 'task_action',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Enabled'),
        'sort' => 'Task.enabled',
        'data_path' => 'Task.enabled',
        'element' => 'enabled',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('User'),
        'sort' => 'User.email',
        'element' => 'custom',
        'function' => function (array $row) use ($baseurl) {
            $label = '<span class="text-muted small"><i class="fas fa-user me-1"></i>' . h(__('User')) . '</span>';
            if (empty($row['User']['email'])) {
                return '<div class="d-flex flex-column gap-1">' . $label
                    . '<span class="text-muted">' . h(__('N/A')) . '</span></div>';
            }
            return sprintf(
                '<div class="d-flex flex-column gap-1">%s<a class="fw-semibold text-decoration-none" href="%s/users/view/%s">%s</a></div>',
                $label,
                h($baseurl),
                h($row['User']['id']),
                h($row['User']['email'])
            );
        },
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Frequency'),
        'sort' => 'Task.timer',
        'data_path' => 'Task.timer',
        'element' => 'custom',
        'function' => function (array $row) use ($formatFrequency) {
            $label = $formatFrequency($row['Task']['timer'] ?? 0);
            if ($label === null) {
                return '<span class="badge rounded-pill text-bg-danger">'
                    . '<i class="fas fa-triangle-exclamation me-1"></i>'
                    . h(__('invalid interval')) . '</span>';
            }
            return '<span class="badge rounded-pill text-bg-light border border-secondary-subtle text-body d-inline-flex align-items-center">'
                . '<i class="fas fa-clock me-1 text-primary"></i>'
                . h($label) . '</span>';
        },
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Last run at'),
        'sort' => 'Task.last_run_at',
        'data_path' => 'Task.last_run_at',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table','card'],
    ],
    [
        'name' => __('Next execution'),
        'sort' => 'Task.next_execution_time',
        'data_path' => 'Task.next_execution_time',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        // Consolidated status: last-job-status badge + the task message beneath.
        'name' => __('Status'),
        'sort' => 'Task.message',
        'data_path' => 'Task.message',
        'element' => 'custom',
        'function' => function (array $row) {
            $message = trim((string)($row['Task']['message'] ?? ''));
            // A task with no last_job_id still comes back with a null-filled Job
            // array (belongsTo left-join), so gate on the real Job id.
            if (empty($row['Job']['id'])) {
                $badge = '<span class="badge rounded-pill text-bg-secondary d-inline-flex align-items-center">'
                    . '<i class="fas fa-circle-minus me-1"></i>' . h(__('No run yet')) . '</span>';
            } else {
                switch ($row['Job']['status']) {
                    case Job::STATUS_COMPLETED:
                        $badge = '<span class="badge rounded-pill text-bg-success d-inline-flex align-items-center">'
                            . '<i class="fas fa-circle-check me-1"></i>' . h(__('Completed')) . '</span>';
                        break;
                    case Job::STATUS_FAILED:
                        $badge = '<span class="badge rounded-pill text-bg-danger d-inline-flex align-items-center">'
                            . '<i class="fas fa-circle-xmark me-1"></i>' . h(__('Failed')) . '</span>';
                        break;
                    case Job::STATUS_RUNNING:
                        $badge = '<span class="badge rounded-pill text-bg-info d-inline-flex align-items-center">'
                            . '<span class="spinner-border spinner-border-sm me-1" style="width:.7em;height:.7em;" role="status"></span>'
                            . h(__('Running')) . '</span>';
                        break;
                    default:
                        $badge = '<span class="badge rounded-pill text-bg-secondary d-inline-flex align-items-center">'
                            . '<i class="fas fa-circle-question me-1"></i>' . h(__('Unknown')) . '</span>';
                }
            }
            $html = '<div class="d-flex flex-column gap-1">' . $badge;
            if ($message !== '') {
                $html .= '<span class="text-body-secondary small text-break">' . h($message) . '</span>';
            }
            $html .= '</div>';
            return $html;
        },
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
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
                'size' => 'md',
            ],
            [
                'type' => 'modal',
                'label' => __('View logs'),
                'icon' => 'file-lines',
                'url' => $baseurl . '/tasks/viewLogs/%id%',
                'requirement' => function ($row) {
                    return !empty($row['Job']['id']);
                },
                'size' => 'xl',
            ],
            [
                'type' => 'modal',
                'label' => __('Enable'),
                'icon' => 'toggle-on',
                'url' => $baseurl . '/tasks/toggleEnabled/%id%',
                'requirement' => function ($row) {
                    return empty($row['Task']['enabled']);
                },
                'size' => 'sm',
            ],
            [
                'type' => 'modal',
                'label' => __('Disable'),
                'icon' => 'toggle-off',
                'url' => $baseurl . '/tasks/toggleEnabled/%id%',
                'requirement' => function ($row) {
                    return !empty($row['Task']['enabled']);
                },
                'size' => 'sm',
            ],
            [
                'type' => 'modal',
                'label' => __('Edit'),
                'icon' => 'pen-to-square',
                'url' => $baseurl . '/tasks/edit/%id%',
            ],
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'size' => 'md',
                'url' => $baseurl . '/tasks/deleteSelection/%id%',
                'class' => 'text-danger',
            ],
        ],
    ],
];

$scaffoldFilterBar = [
    'children' => [
        [
            'type' => 'search',
            'mode' => 'quickFilter',
            'name' => 'quickFilter',
            'placeholder' => __('Search type, action, parameters or description'),
        ],
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'name' => 'type',
                    'label' => __('Type'),
                    'options' => [
                        '' => __('All types'),
                        'Server' => __('Server'),
                        'Feed' => __('Feed'),
                        'Workflow' => __('Workflow'),
                        'Periodic Summary' => __('Periodic Summary'),
                        'TAXII' => __('TAXII'),
                        'Admin' => __('Admin'),
                    ],
                ],
                [
                    'type' => 'dropdown',
                    'name' => 'enabled',
                    'label' => __('Status'),
                    'options' => [
                        '' => __('All'),
                        '1' => __('Enabled'),
                        '0' => __('Disabled'),
                    ],
                ],
            ],
        ],
    ],
    'delete' => '/deleteSelection',
    'delete_url' => '/tasks/deleteSelection',
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
            'filter_bar' => $scaffoldFilterBar,
            'fields' => $fields,
        ],
    ],
    'item_url' => '/tasks',
]);
