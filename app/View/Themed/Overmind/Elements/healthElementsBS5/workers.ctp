<?php
/**
 * Workers tab of the server settings.
 *
 * Unlike the settings tabs this one is a live view of the worker processes,
 * so it carries actions: start/stop a worker, clear a queue, restart the dead
 * ones, kill everything. They are plain CakePHP postLinks — POST + redirect
 * back to this tab.
 *
 * Every queue card is expanded by default: this is a monitoring view, and
 * collapsing it would hide exactly what the page is opened for.
 *
 * Params: worker_array (Server::workerDiagnostics)
 */

App::uses('BackgroundJobsTool', 'Tools');

$controls = !empty($worker_array['controls']);
$procAccessible = !empty($worker_array['proc_accessible']);
$supervisorEnabled = (bool)Configure::read('SimpleBackgroundJobs.enabled');
$supervisorDown = $supervisorEnabled && empty($worker_array['supervisord_status']);

$queueMeta = array(
    'default' => array(
        'title' => __('Default queue'),
        'description' => __('General purpose background jobs'),
        'icon' => 'list-check',
        'accent' => '#0d6efd',
    ),
    'prio' => array(
        'title' => __('Priority queue'),
        'description' => __('Jobs kept responsive for interactive work'),
        'icon' => 'bolt',
        'accent' => '#fd7e14',
    ),
    'email' => array(
        'title' => __('E-mail queue'),
        'description' => __('Outgoing notification e-mails'),
        'icon' => 'envelope',
        'accent' => '#198754',
    ),
    'cache' => array(
        'title' => __('Cache queue'),
        'description' => __('Export and feed caching jobs'),
        'icon' => 'database',
        'accent' => '#d63384',
    ),
    'update' => array(
        'title' => __('Update queue'),
        'description' => __('Database and data model updates — only one worker may run at a time'),
        'icon' => 'arrows-rotate',
        'accent' => '#6f42c1',
    ),
    'scheduler' => array(
        'title' => __('Scheduler'),
        'description' => __('Fires the recurring tasks at their scheduled time'),
        'icon' => 'clock',
        'accent' => '#0dcaf0',
    ),
);

// Everything that goes through the confirmation modal, keyed by the id of the
// hidden postLink it triggers. Emitted as JSON into the script below so no
// escaped string ever lands in an onclick attribute.
$confirmations = array();

$uid = 'wk' . dechex(mt_rand());

if (empty($worker_array)) {
    echo sprintf(
        '<div class="card shadow-sm"><div class="card-body text-center text-muted py-5">'
            . '<i class="fas fa-robot fa-2x mb-3 d-block opacity-50"></i>%s</div></div>',
        h(__('Background jobs are disabled on this instance, so there is no worker to report on.'))
    );
    return;
}
?>
<div class="ss-scope" id="<?= h($uid) ?>">

    <!-- WARNINGS -->
    <?php if (!$procAccessible): ?>
        <div class="alert alert-danger d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('MISP cannot access your /proc directory to check the status of the worker processes, which means that dead workers will not be detected by the diagnostic tool. If you would like to regain this functionality, make sure that the open_basedir directive is not set, or that /proc is included in it.') ?></div>
        </div>
    <?php endif; ?>

    <?php if ($supervisorDown): ?>
        <div class="alert alert-danger d-flex gap-2" role="alert">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('MISP cannot connect to the Supervisord API, check the following settings are correct: [`supervisor_host`, `supervisor_port`, `supervisor_user`, `supervisor_password`] and restart the service. For details check the MISP error logs.') ?></div>
        </div>
    <?php endif; ?>

    <?php if (!$controls): ?>
        <div class="alert alert-secondary d-flex gap-2" role="alert">
            <i class="fas fa-circle-info mt-1"></i>
            <div><?= __('The "manage_workers" setting is set to "false", therefore worker controls have been disabled.') ?></div>
        </div>
    <?php endif; ?>

    <!-- GLOBAL ACTIONS -->
    <?php if ($controls): ?>
        <?php
            $confirmations['wk-kill'] = array(
                'title' => __('Kill all workers'),
                'body' => '<p class="mb-0 text-muted small">' . h(__('Every worker will be asked to stop. Jobs currently being processed are allowed to finish first.')) . '</p>',
                'label' => __('Kill all workers'),
                'cls' => 'btn-warning',
            );
            $confirmations['wk-kill-force'] = array(
                'title' => __('Force kill all workers'),
                'body' => '<p class="mb-0 text-muted small">' . h(__('This issues a kill -9 and terminates any processing currently underway. Jobs in flight will be lost.')) . '</p>',
                'label' => __('Force kill'),
                'cls' => 'btn-danger',
            );
        ?>
        <div class="card shadow-sm mb-4">
            <div class="card-body d-flex flex-wrap gap-2 align-items-center">
                <span class="text-muted" style="font-size:.85rem;">
                    <?= __('Worker controls apply to every queue at once.') ?>
                </span>
                <div class="ms-auto d-flex flex-wrap gap-2">
                    <?= $this->Form->postLink(
                        '<i class="fas fa-heart-pulse me-1"></i>' . __('Restart dead workers'),
                        $baseurl . '/servers/restartDeadWorkers',
                        array('class' => 'btn btn-outline-primary', 'escape' => false)
                    ) ?>
                    <button type="button" class="btn btn-outline-warning"
                            onclick="wkConfirm('wk-kill')">
                        <i class="fas fa-power-off me-1"></i><?= __('Kill all workers') ?>
                    </button>
                    <button type="button" class="btn btn-outline-danger"
                            onclick="wkConfirm('wk-kill-force')">
                        <i class="fas fa-skull me-1"></i><?= __('Force kill all workers') ?>
                    </button>
                </div>
            </div>
        </div>

        <?= $this->Form->postLink('', $baseurl . '/servers/killAllWorkers',
            array('id' => 'wk-kill', 'class' => 'd-none', 'escape' => false)) ?>
        <?= $this->Form->postLink('', $baseurl . '/servers/killAllWorkers/1',
            array('id' => 'wk-kill-force', 'class' => 'd-none', 'escape' => false)) ?>
    <?php endif; ?>

    <!-- ONE CARD PER QUEUE -->
    <?php foreach ($worker_array as $type => $data): ?>
        <?php
        if (!in_array($type, BackgroundJobsTool::VALID_QUEUES, true)) {
            continue;
        }
        $meta = isset($queueMeta[$type]) ? $queueMeta[$type] : array(
            'title' => $type,
            'description' => __('Background job queue'),
            'icon' => 'list-check',
            'accent' => '#6c757d',
        );

        // Queue health
        $queueStatusMessage = __('Issues prevent jobs from being processed. Please resolve them below.');
        $queueLevel = 0;
        if (!empty($data['ok'])) {
            if (!$procAccessible) {
                $queueLevel = 1;
                $queueStatusMessage = __('Worker started with the correct user, but the current status is unknown.');
            } else {
                $queueLevel = 2;
                $queueStatusMessage = __('OK');
            }
        } elseif (!empty($data['workers'])) {
            foreach ($data['workers'] as $worker) {
                if ($worker['alive']) {
                    $queueLevel = 2;
                    $queueStatusMessage = __('There are issues with the worker(s), but at least one healthy worker is monitoring the queue.');
                    break;
                }
            }
        }

        $collapseId = $uid . '_' . $type;
        $workerCount = isset($data['workers']) ? count($data['workers']) : 0;
        $jobCount = isset($data['jobCount']) ? (int)$data['jobCount'] : null;
        ?>
        <div class="card shadow-sm mb-3 ss-section" style="--ss-accent: <?= h($meta['accent']) ?>;">

            <div class="card-header ss-section-header"
                 data-bs-toggle="collapse"
                 data-bs-target="#<?= h($collapseId) ?>"
                 aria-expanded="true"
                 aria-controls="<?= h($collapseId) ?>">

                <span class="ss-section-icon"><i class="fas fa-<?= h($meta['icon']) ?>"></i></span>

                <div class="flex-grow-1">
                    <div class="fw-semibold"><?= h($meta['title']) ?></div>
                    <div class="text-muted" style="font-size:.78rem;"><?= h($meta['description']) ?></div>
                </div>

                <?php if ($jobCount !== null): ?>
                    <span class="badge rounded-pill bg-body-tertiary text-body-secondary"
                          title="<?= h(__('Jobs waiting in the queue')) ?>">
                        <i class="fas fa-inbox me-1"></i><?= h($jobCount) ?>
                    </span>
                <?php endif; ?>

                <span class="badge rounded-pill bg-body-tertiary text-body-secondary"
                      title="<?= h(__('Workers monitoring this queue')) ?>">
                    <i class="fas fa-microchip me-1"></i><?= h($workerCount) ?>
                </span>

                <span class="ss-prio ss-lvl-<?= (int)$queueLevel ?>">
                    <i class="fas fa-<?= $queueLevel === 2 ? 'circle-check' : ($queueLevel === 1 ? 'circle-question' : 'circle-xmark') ?>"></i>
                    <?= $queueLevel === 2 ? __('OK') : ($queueLevel === 1 ? __('Unknown') : __('Down')) ?>
                </span>

                <i class="fas fa-chevron-up ss-chevron"></i>
            </div>

            <div id="<?= h($collapseId) ?>" class="collapse show">

                <?php // Only worth a strip when it says more than the header pill already does. ?>
                <?php if ($queueLevel !== 2 || !empty($data['workers']) && !$data['ok']): ?>
                    <div class="ss-section-alert <?= $queueLevel === 1 ? 'ss-alert-warn' : ($queueLevel === 2 ? 'ss-alert-ok' : '') ?>">
                        <i class="fas fa-circle-info me-1"></i><?= h($queueStatusMessage) ?>
                    </div>
                <?php endif; ?>

                <div class="table-responsive">
                    <table class="table table-sm align-middle ss-table mb-0">
                        <thead>
                            <tr>
                                <th style="width:8rem;"><?= __('Worker PID') ?></th>
                                <th style="width:10rem;"><?= __('User') ?></th>
                                <th style="width:9rem;"><?= __('Process') ?></th>
                                <th><?= __('Information') ?></th>
                                <th style="width:6rem;"><?= __('Actions') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php if (empty($data['workers'])): ?>
                            <tr class="ss-row ss-row-error ss-lvl-0">
                                <td colspan="4" class="text-danger fw-semibold">
                                    <i class="fas fa-circle-xmark me-1"></i><?= __('Worker not running!') ?>
                                </td>
                                <td></td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($data['workers'] as $worker): ?>
                                <?php
                                $level = 2;
                                $process = __('OK');
                                $message = __('The worker appears to be healthy.');
                                if ($worker['correct_user'] !== true) {
                                    if ($worker['alive']) {
                                        $level = 1;
                                        $message = __('The worker appears to be healthy, but cannot determine the user of the process, most likely due to SELinux blocking MISP\'s access to it.');
                                    } else {
                                        $level = 0;
                                        $process = __('Unknown');
                                        $message = __('The worker was started with a user other than the apache user. MISP cannot check whether or not the worker is alive.');
                                    }
                                } elseif ($worker['alive'] === 'N/A') {
                                    $level = 1;
                                    $process = __('Unknown');
                                    $message = __('Cannot check whether the worker is dead or alive.');
                                } elseif (!$worker['alive']) {
                                    $level = 0;
                                    $process = __('Dead');
                                    $message = __('The worker appears to be dead.');
                                }

                                $stopId = 'wk-stop-' . h($worker['pid']);
                                if ($controls) {
                                    $confirmations[$stopId] = array(
                                        'title' => __('Stop worker %s', $worker['pid']),
                                        'body' => '<p class="mb-0 text-muted small">'
                                            . h(__('This stops the worker if it is still running and removes it. Any job it is currently executing is terminated immediately.'))
                                            . '</p>',
                                        'label' => __('Stop this worker'),
                                        'cls' => 'btn-danger',
                                    );
                                }
                                ?>
                                <tr class="ss-row <?= $level < 2 ? 'ss-row-error ss-lvl-' . $level : '' ?>">
                                    <td><span class="ss-setting-name"><?= h($worker['pid']) ?></span></td>
                                    <td><span class="ss-setting-name"><?= h($worker['user']) ?></span></td>
                                    <td>
                                        <span class="ss-prio ss-lvl-<?= (int)$level ?>">
                                            <i class="fas fa-<?= $level === 2 ? 'circle-check' : ($level === 1 ? 'circle-question' : 'circle-xmark') ?>"></i>
                                            <?= h($process) ?>
                                        </span>
                                    </td>
                                    <td class="text-muted" style="font-size:.76rem;"><?= h($message) ?></td>
                                    <td>
                                        <?php if ($controls): ?>
                                            <button type="button" class="btn btn-sm btn-outline-danger"
                                                    onclick="wkConfirm('<?= h($stopId) ?>')"
                                                    title="<?= h(__('Stop and remove this worker')) ?>">
                                                <i class="fas fa-stop"></i>
                                            </button>
                                            <?= $this->Form->postLink('', $baseurl . '/servers/stopWorker/' . h($worker['pid']),
                                                array('id' => $stopId, 'class' => 'd-none', 'escape' => false)) ?>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        </tbody>
                    </table>
                </div>

                <?php if ($type === 'scheduler' && empty($data['workers'])): ?>
                    <div class="alert alert-warning m-3" role="alert">
                        <p><?= __('The task scheduler is not enabled. To enable it please add the missing %s program configuration to your supervisor configuration file (%s).',
                            '<code>scheduler</code>', '<code>/etc/supervisor/conf.d/*-workers.conf</code>') ?></p>
                        <p><?= __('You can find the sample configuration file in %s.', '<code>build/supervisor/50-workers.conf</code>') ?></p>
                        <p class="mb-0"><?= __('For more information, please refer to the %s.',
                            '<a href="https://github.com/MISP/MISP/wiki/Supervisor-Task-Scheduler-Guide-(2.5)" target="_blank" rel="noreferrer">' . __('MISP documentation') . '</a>') ?></p>
                    </div>
                <?php endif; ?>

                <?php if ($controls): ?>
                    <?php
                    $startId = 'wk-start-' . h($type);
                    $clearId = 'wk-clear-' . h($type);
                    if (!empty($jobCount)) {
                        $confirmations[$clearId] = array(
                            'title' => __('Clear the %s queue', $type),
                            'body' => '<p class="mb-0 text-muted small">'
                                . h(__('The %s job(s) waiting in this queue will be dropped and never executed.', $jobCount))
                                . '</p>',
                            'label' => __('Clear the queue'),
                            'cls' => 'btn-danger',
                        );
                    }
                    ?>
                    <div class="d-flex flex-wrap gap-2 p-3 border-top">
                        <?= $this->Form->postLink(
                            '<i class="fas fa-play me-1"></i>' . __('Start a worker'),
                            $baseurl . '/servers/startWorker/' . h($type),
                            array('class' => 'btn btn-sm btn-outline-primary', 'escape' => false)
                        ) ?>
                        <?php if (!empty($jobCount)): ?>
                            <button type="button" class="btn btn-sm btn-outline-danger"
                                    onclick="wkConfirm('<?= h($clearId) ?>')">
                                <i class="fas fa-trash me-1"></i><?= __('Clear the queue') ?>
                            </button>
                            <?= $this->Form->postLink('', $baseurl . '/servers/clearWorkerQueue/' . h($type),
                                array('id' => $clearId, 'class' => 'd-none', 'escape' => false)) ?>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

            </div>
        </div>
    <?php endforeach; ?>

</div>

<script>
(function () {
    var WK = <?= json_encode($confirmations, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var CANCEL = <?= json_encode(__('Cancel')) ?>;

    window.wkConfirm = function (id) {
        var conf = WK[id];
        var trigger = document.getElementById(id);
        if (!conf || !trigger) return;
        showConfirmModal({
            title: conf.title,
            body: conf.body,
            confirmLabel: conf.label,
            confirmClass: conf.cls,
            cancelLabel: CANCEL,
            onConfirm: function () { trigger.click(); }
        });
    };
})();
</script>
