<?php
// Overmind BS5 logs fragment injected into #mainModalBody by openModal().
// Read-only card: the associated Job's details plus any error output/backtrace.
// The controller sets $task (with $task['Job'] and $task['Org']) and $logs.
$job = $task['Job'];
$rows = [
    __('ID') => $job['id'] ?? '',
    __('Type') => $job['job_type'] ?? '',
    __('Input') => $job['job_input'] ?? '',
    __('Worker') => $job['worker'] ?? '',
    __('Org') => $task['Org']['Organisation']['name'] ?? ($task['Org']['name'] ?? ''),
    __('Status') => $job['status'] ?? '',
    __('Progress') => (isset($job['progress']) ? $job['progress'] . '%' : ''),
    __('Retries') => $job['retries'] ?? '',
    __('Message') => $job['message'] ?? '',
    __('Process ID') => $job['process_id'] ?? '',
    __('Created') => $job['date_created'] ?? '',
    __('Modified') => $job['date_modified'] ?? '',
];
?>
<div class="card shadow-sm">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h4 class="card-title mb-0">
            <i class="fas fa-cogs me-2"></i><?= __('View Task #%s Logs', h($task['Task']['id'])) ?>
        </h4>
        <button
            type="button"
            class="btn btn-outline-secondary btn-sm"
            onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
            <i class="fas fa-xmark me-1"></i><?= __('Close') ?>
        </button>
    </div>
    <div class="card-body">
        <h5 class="mb-3"><i class="fas fa-cogs me-2"></i><?= __('Job Details') ?></h5>
        <table class="table table-striped table-bordered align-middle">
            <tbody>
                <?php foreach ($rows as $label => $value): ?>
                    <tr>
                        <th class="w-25"><?= h($label) ?></th>
                        <td><?= h($value) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if (!empty($logs['error'])): ?>
            <hr>
            <h5 class="mb-3"><i class="fas fa-bug me-2"></i><?= __('Error Log') ?></h5>
            <div class="alert alert-danger">
                <strong><?= __('Error:') ?></strong> <?= h($logs['error']) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($logs['backtrace']) && $logs['backtrace'][0] !== ''): ?>
            <h5 class="mb-2"><?= __('Backtrace') ?></h5>
            <pre class="bg-body-tertiary border p-3 rounded small mb-0" style="max-height:300px; overflow:auto;"><?= h(implode("\n", $logs['backtrace'])) ?></pre>
        <?php endif; ?>
    </div>
</div>
