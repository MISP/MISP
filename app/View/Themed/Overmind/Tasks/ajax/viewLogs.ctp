<?php

$job = $task['Job'];
$orgName = $task['Org']['Organisation']['name'] ?? ($task['Org']['name'] ?? '');

$statusMap = [
    Job::STATUS_WAITING   => ['label' => __('Waiting'),   'class' => 'text-bg-secondary', 'icon' => 'fa-hourglass-half', 'bar' => 'bg-secondary'],
    Job::STATUS_RUNNING   => ['label' => __('Running'),   'class' => 'text-bg-info',      'icon' => 'fa-spinner fa-spin', 'bar' => 'bg-info'],
    Job::STATUS_FAILED    => ['label' => __('Failed'),    'class' => 'text-bg-danger',    'icon' => 'fa-circle-xmark',    'bar' => 'bg-danger'],
    Job::STATUS_COMPLETED => ['label' => __('Completed'), 'class' => 'text-bg-success',   'icon' => 'fa-circle-check',    'bar' => 'bg-success'],
];
$status = isset($job['status']) ? (int)$job['status'] : null;
$si = $statusMap[$status] ?? ['label' => __('Unknown'), 'class' => 'text-bg-secondary', 'icon' => 'fa-circle-question', 'bar' => 'bg-secondary'];

$progress = isset($job['progress']) && $job['progress'] !== '' ? (int)$job['progress'] : null;
$message = trim((string)($job['message'] ?? ''));

// One labeled detail cell (muted uppercase label + value, "—" when empty).
$detail = function ($label, $value, $icon) {
    $value = (is_string($value) || is_numeric($value)) ? trim((string)$value) : '';
    ob_start(); ?>
    <div class="col">
        <div class="d-flex align-items-center gap-1 text-muted text-uppercase mb-1"
             style="font-size:.62rem; letter-spacing:.06em;">
            <i class="fas <?= h($icon) ?>"></i><?= h($label) ?>
        </div>
        <?php if ($value === ''): ?>
            <div class="text-muted">&mdash;</div>
        <?php else: ?>
            <div class="fw-semibold text-break"><?= h($value) ?></div>
        <?php endif; ?>
    </div>
    <?php return ob_get_clean();
};
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06); border-bottom:2px solid var(--bs-primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Scheduled Tasks') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-file-lines text-primary" style="font-size:1.25rem;"></i>
            <?= __('Task #%s — Job logs', h($task['Task']['id'])) ?>
        </h4>
    </div>
    <button type="button" class="btn btn-sm btn-outline-secondary"
            onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
        <i class="fas fa-xmark"></i>
    </button>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ══ STATUS HERO ═══════════════════════════════════════ -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center flex-wrap gap-2 mb-2">
                <span class="badge rounded-pill <?= h($si['class']) ?> d-inline-flex align-items-center fs-6 px-3 py-2">
                    <i class="fas <?= h($si['icon']) ?> me-2"></i><?= h($si['label']) ?>
                </span>
                <?php if (!empty($job['job_type'])): ?>
                    <span class="badge rounded-pill bg-body-secondary text-body border border-secondary-subtle">
                        <i class="fas fa-gears me-1"></i><?= h($job['job_type']) ?>
                    </span>
                <?php endif; ?>
                <?php if (!empty($job['worker'])): ?>
                    <span class="badge rounded-pill bg-body-secondary text-body border border-secondary-subtle">
                        <i class="fas fa-microchip me-1"></i><?= h($job['worker']) ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if ($progress !== null): ?>
                <div class="progress" role="progressbar" aria-valuenow="<?= h($progress) ?>"
                     aria-valuemin="0" aria-valuemax="100" style="height:1.1rem;">
                    <div class="progress-bar <?= h($si['bar']) ?> fw-semibold<?= $status === Job::STATUS_RUNNING ? ' progress-bar-striped progress-bar-animated' : '' ?>"
                         style="width:<?= h($progress) ?>%;">
                        <?= h($progress) ?>%
                    </div>
                </div>
            <?php endif; ?>

            <?php if ($message !== ''): ?>
                <div class="text-body-secondary small mt-2">
                    <i class="fas fa-comment-dots me-1"></i><?= h($message) ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- ══ JOB DETAILS ═══════════════════════════════════════ -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Job details') ?>
            </div>
            <div class="row row-cols-1 row-cols-sm-2 row-cols-lg-3 g-3">
                <?= $detail(__('Job ID'), $job['id'] ?? '', 'fa-hashtag') ?>
                <?= $detail(__('Type'), $job['job_type'] ?? '', 'fa-tag') ?>
                <?= $detail(__('Worker'), $job['worker'] ?? '', 'fa-microchip') ?>
                <?= $detail(__('Organisation'), $orgName, 'fa-building') ?>
                <?= $detail(__('Process ID'), $job['process_id'] ?? '', 'fa-fingerprint') ?>
                <?= $detail(__('Retries'), $job['retries'] ?? '', 'fa-rotate-right') ?>
                <?= $detail(__('Created'), $job['date_created'] ?? '', 'fa-calendar-plus') ?>
                <?= $detail(__('Modified'), $job['date_modified'] ?? '', 'fa-calendar-check') ?>
                <?= $detail(__('Input'), $job['job_input'] ?? '', 'fa-right-to-bracket') ?>
            </div>
        </div>

        <!-- ══ ERROR ═════════════════════════════════════════════ -->
        <?php if (!empty($logs['error'])): ?>
            <div class="w-100 px-2">
                <div class="text-danger fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Error log') ?>
                </div>
                <div class="alert alert-danger d-flex align-items-start gap-2 mb-0" role="alert">
                    <i class="fas fa-bug mt-1"></i>
                    <div class="text-break"><?= h($logs['error']) ?></div>
                </div>
            </div>
        <?php endif; ?>

        <!-- ══ BACKTRACE ═════════════════════════════════════════ -->
        <?php if (!empty($logs['backtrace']) && $logs['backtrace'][0] !== ''): ?>
            <div class="w-100 px-2">
                <div class="text-primary fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Backtrace') ?>
                </div>
                <pre class="bg-body-tertiary border rounded p-3 small mb-0 font-monospace"
                     style="max-height:280px; overflow:auto;"><?= h(implode("\n", $logs['backtrace'])) ?></pre>
            </div>
        <?php endif; ?>
    </div>
</div>
