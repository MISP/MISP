<?php

$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;

$this->set('headerTitle', __('Jobs'));
$this->set('headerDescription', __('Background jobs queued or executed on this instance. Job entries are log records and have no impact on running jobs; purging them is safe.'));
$this->set('headerActions', [
    [
        'type' => 'action',
        'label' => __('Purge completed'),
        'icon' => 'broom',
        'url' => ['controller' => 'jobs', 'action' => 'clearJobs'],
        'confirm' => __('Are you sure you want to purge all completed job entries? Job entries are log entries and have no impact on actual job execution.'),
    ],
    [
        'type' => 'action',
        'label' => __('Purge all'),
        'icon' => 'trash',
        'url' => ['controller' => 'jobs', 'action' => 'clearJobs', 'all'],
        'confirm' => __('Are you sure you want to purge all job entries? Job entries are log entries and have no impact on actual job execution.'),
    ],
]);

// Colour a queue name consistently between the badge column and the filter.
$workerVariant = function ($worker) {
    switch ($worker) {
        case 'prio':    return 'danger';
        case 'email':   return 'info';
        case 'cache':   return 'warning';
        case 'update':  return 'primary';
        case 'default': return 'secondary';
        default:        return 'light';
    }
};

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Job.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('ID'),
        'sort' => 'Job.id',
        'data_path' => 'Job.id',
        'element' => 'id',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('ID'),
        'sort' => 'Job.process_id',
        'data_path' => 'Job.process_id',
        'element' => 'uuid',
        'url' => '#',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Queue / Type'),
        'sort' => 'worker',
        'element' => 'custom',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) use ($workerVariant) {
            $worker = $row['Job']['worker'] ?? '';
            $type = $row['Job']['job_type'] ?? '';
            $out = '<div class="d-flex flex-column gap-1">';
            if ($worker !== '') {
                $out .= '<span class="badge rounded-pill text-bg-' . $workerVariant($worker)
                    . ' align-self-start"><i class="fas fa-diagram-project me-1"></i>'
                    . h($worker) . '</span>';
            }
            if ($type !== '') {
                $out .= '<span class="font-monospace small text-body-secondary text-break">'
                    . h($type) . '</span>';
            }
            $out .= '</div>';
            return $out;
        },
    ],
    [
        'name' => __('Details'),
        'element' => 'custom',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'style' => 'max-width: 320px;',
        'function' => function (array $row) {
            $input = trim((string)($row['Job']['job_input'] ?? ''));
            $message = trim((string)($row['Job']['message'] ?? ''));
            if ($input === '' && $message === '') {
                return '<span class="text-muted">' . h(__('N/A')) . '</span>';
            }
            $out = '<div class="d-flex flex-column gap-1">';
            if ($input !== '') {
                $out .= '<code class="d-inline-block text-truncate" style="max-width: 320px;" title="'
                    . h($input) . '">' . h($input) . '</code>';
            }
            if ($message !== '') {
                $out .= '<span class="text-body-secondary small text-truncate" style="max-width: 320px;" title="'
                    . h($message) . '">' . h($message) . '</span>';
            }
            $out .= '</div>';
            return $out;
        },
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Org.name',
        'element' => 'custom',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) {
            return isset($row['Org']['name'])
                ? '<span class="d-inline-flex align-items-center"><i class="fas fa-building me-1 text-muted"></i>'
                    . h($row['Org']['name']) . '</span>'
                : '<span class="text-muted d-inline-flex align-items-center"><i class="fas fa-gear me-1"></i>'
                    . h(__('SYSTEM')) . '</span>';
        },
    ],
    [
        'name' => __('Created'),
        'sort' => 'date_created',
        'data_path' => 'Job.date_created',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Modified'),
        'sort' => 'date_modified',
        'data_path' => 'Job.date_modified',
        'element' => 'datetime',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Status'),
        'sort' => 'status',
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) use ($baseurl) {
            $status = $row['Job']['job_status'] ?? __('Unknown');
            $failed = !empty($row['Job']['failed'])
                || (isset($row['Job']['status']) && (int)$row['Job']['status'] === Job::STATUS_FAILED);
            $variant = 'secondary';
            if ($failed) {
                $status = __('Failed');
                $variant = 'danger';
            } elseif ($status === 'Completed') {
                $variant = 'success';
            } elseif ($status === 'Running') {
                $variant = 'info';
            } elseif ($status === 'Queued' || $status === 'Waiting') {
                $variant = 'warning';
            }
            $out = '<span class="badge text-bg-' . $variant . '">' . h($status) . '</span>';
            if ($failed && !empty($row['Job']['process_id'])) {
                $url = $baseurl . '/jobs/getError/' . h($row['Job']['process_id']);
                $out .= ' <a href="' . $url . '"'
                    . ' title="' . h(__('View stacktrace')) . '"'
                    . ' onclick="event.preventDefault(); openModal(\'' . $url . '\', \'lg\');"'
                    . ' class="text-danger ms-1"><i class="fas fa-magnifying-glass"></i></a>';
            }
            return $out;
        },
    ],
    [
        'name' => __('Progress'),
        'sort' => 'progress',
        'element' => 'progress',
        'style' => 'min-width: 200px;',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
        'function' => function (array $row) {
            $job = $row['Job'];
            $failed = !empty($job['failed'])
                || (isset($job['status']) && (int)$job['status'] === Job::STATUS_FAILED);
            $workerOk = !empty($job['worker_status']);
            $progress = (int)($job['progress'] ?? 0);
            if ($failed) {
                return ['percent' => 100, 'label' => __('Failed'), 'variant' => 'danger'];
            }
            if (!$workerOk && $progress !== 100) {
                return ['percent' => 100, 'label' => __('No worker active'), 'variant' => 'warning', 'striped' => true, 'animated' => true];
            }
            if ($progress === 0) {
                $label = (($job['job_status'] ?? '') === 'Running') ? __('Running') : __('Queued');
                return ['percent' => 100, 'label' => $label, 'variant' => 'info', 'striped' => true, 'animated' => true, 'refresh' => true];
            }
            if ($progress === 100) {
                return ['percent' => 100, 'label' => __('Completed'), 'variant' => 'success'];
            }
            return ['percent' => $progress, 'label' => $progress . '%', 'variant' => 'primary', 'striped' => true, 'animated' => true, 'refresh' => true];
        },
    ],
];

if ($isSiteAdmin) {
    $fields[] = [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Job.id',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'size' => 'md',
                'url' => $baseurl . '/jobs/deleteSelection/%id%',
                'class' => 'text-danger',
            ],
        ],
    ];
}

$scaffoldFilterBar = [
    'children' => [
        [
            'type' => 'search',
            'mode' => 'quickFilter',
            'name' => 'quickFilter',
            'placeholder' => __('Search worker, type, input, message or process ID'),
        ],
        [
            'type' => 'more_filters',
            'label' => __('More filters'),
            'children' => [
                [
                    'type' => 'dropdown',
                    'name' => 'worker',
                    'label' => __('Queue'),
                    'options' => [
                        ''        => __('All queues'),
                        'default' => __('Default'),
                        'prio'    => __('Prio'),
                        'email'   => __('Email'),
                        'cache'   => __('Cache'),
                        'update'  => __('Update'),
                    ],
                ],
            ],
        ],
    ],
];

if ($isSiteAdmin) {
    $scaffoldFilterBar['delete'] = '/deleteSelection';
    $scaffoldFilterBar['delete_url'] = '/jobs/deleteSelection';
}

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Job.id',
            'fields' => $fields,
            'filter_bar' => $scaffoldFilterBar,
        ],
    ],
    'item_url' => '/jobs',
]);
?>
<script>
(function () {
    var baseurl = <?= json_encode($baseurl) ?>;
    var refreshIds = [];
    document.querySelectorAll('[data-progress-refresh="1"]').forEach(function (barWrap) {
        var tr = barWrap.closest('tr[data-primary-id]');
        if (tr) { refreshIds.push(tr.dataset.primaryId); }
    });
    if (!refreshIds.length) { return; }

    var interval = setInterval(function () {
        if (document.hidden) { return; }
        if (!refreshIds.length) { clearInterval(interval); return; }
        fetch(baseurl + '/jobs/getGenerateCorrelationProgress/' + refreshIds.join(','), {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        }).then(function (r) { return r.ok ? r.json() : {}; })
          .then(function (allData) {
            Object.keys(allData).forEach(function (id) {
                var data = allData[id];
                var tr = document.querySelector('tr[data-primary-id="' + id + '"]');
                if (!tr) { return; }
                var bar = tr.querySelector('.progress-bar');
                if (!bar) { return; }
                if (data.progress == 0) {
                    bar.textContent = data.job_status;
                } else if (data.progress > 0 && data.progress < 100) {
                    bar.style.width = data.progress + '%';
                    bar.textContent = data.progress + '%';
                } else if (data.progress == 100) {
                    bar.style.width = '100%';
                    bar.textContent = data.job_status;
                    bar.className = 'progress-bar bg-success';
                    refreshIds = refreshIds.filter(function (e) { return e != id; });
                }
            });
        }).catch(function () {});
    }, 3000);
}());
</script>
