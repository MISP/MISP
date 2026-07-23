<?php
// Overmind BS5 index for background jobs. Migrates the legacy hand-rolled
// Paginator table (app/View/Jobs/index.ctp) to the parametrised BS5 scaffold.
// Read-only: index() is site-admin only and offers no per-row delete — only the
// bulk purge (Completed / All) header actions and the queue filter tabs. The
// live progress bars self-refresh via getGenerateCorrelationProgress (CSRF-exempt),
// polled with a plain fetch since jQuery isn't loaded under Overmind.
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

// Queue filter tabs (positional arg on /jobs/index/<queue>).
$queues = [
    ''        => __('All'),
    'default' => __('Default'),
    'prio'    => __('Prio'),
    'email'   => __('Email'),
    'cache'   => __('Cache'),
];
$queueButtons = [];
foreach ($queues as $q => $qLabel) {
    $active = ($q === '') ? empty($queue) : ($queue === $q);
    $queueButtons[] = [
        'type'  => 'button',
        'label' => $qLabel,
        'url'   => $baseurl . '/jobs/index' . ($q === '' ? '' : '/' . $q),
        'class' => 'btn ' . ($active ? 'btn-primary' : 'btn-outline-primary') . ' fw-semibold',
    ];
}

$fields = [
    [
        'name' => __('ID'),
        'sort' => 'id',
        'data_path' => 'Job.id',
    ],
    [
        'name' => __('Date created'),
        'sort' => 'date_created',
        'data_path' => 'Job.date_created',
        'element' => 'datetime',
    ],
    [
        'name' => __('Date modified'),
        'sort' => 'date_modified',
        'data_path' => 'Job.date_modified',
        'element' => 'datetime',
    ],
    [
        'name' => __('Process ID'),
        'sort' => 'process_id',
        'data_path' => 'Job.process_id',
    ],
    [
        'name' => __('Worker'),
        'sort' => 'worker',
        'data_path' => 'Job.worker',
    ],
    [
        'name' => __('Job type'),
        'sort' => 'job_type',
        'data_path' => 'Job.job_type',
    ],
    [
        'name' => __('Input'),
        'sort' => 'job_input',
        'data_path' => 'Job.job_input',
    ],
    [
        'name' => __('Message'),
        'sort' => 'message',
        'data_path' => 'Job.message',
    ],
    [
        'name' => __('Organisation'),
        'sort' => 'Org.name',
        'element' => 'custom',
        'function' => function (array $row) {
            return isset($row['Org']['name'])
                ? '<span>' . h($row['Org']['name']) . '</span>'
                : '<span class="text-muted">' . h(__('SYSTEM')) . '</span>';
        },
    ],
    [
        'name' => __('Status'),
        'sort' => 'status',
        'element' => 'custom',
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

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $data,
            'primary_id_path' => 'Job.id',
            'fields' => $fields,
            'filter_bar' => [
                'children' => $queueButtons,
            ],
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
