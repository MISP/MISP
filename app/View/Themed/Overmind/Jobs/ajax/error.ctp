<?php
// Overmind BS5 stacktrace fragment injected into #mainModalBody by openModal()
// from the Jobs index (failed-job magnifier). BS5 re-skin of the legacy
// app/View/Jobs/ajax/error.ctp. The controller (getError) sets $fields
// (label => response key) and $response ('error' + 'backtrace', or the
// CakeResque failed_at/exception/error shape).
$hasData = !empty($response);
$backtrace = '';
if (!empty($response['backtrace'])) {
    $backtrace = implode("\n", array_filter($response['backtrace'], function ($l) {
        return $l !== '';
    }));
}
?>
<div class="card shadow-sm">
    <div class="card-header d-flex justify-content-between align-items-center">
        <h4 class="card-title mb-0">
            <i class="fas fa-triangle-exclamation me-2 text-danger"></i><?= __('Background Job Error Browser') ?>
        </h4>
        <button type="button" class="btn btn-outline-secondary btn-sm"
            onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
            <i class="fas fa-xmark me-1"></i><?= __('Close') ?>
        </button>
    </div>
    <div class="card-body">
        <?php if ($hasData): ?>
            <table class="table table-striped table-bordered align-middle">
                <tbody>
                    <?php foreach ($fields as $name => $content): ?>
                        <?php if (isset($response[$content]) && $response[$content] !== ''): ?>
                            <tr>
                                <th class="w-25 text-danger"><?= h($name) ?></th>
                                <td><?= h($response[$content]) ?></td>
                            </tr>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php if ($backtrace !== ''): ?>
                <h5 class="mb-2"><?= __('Stack trace') ?></h5>
                <pre class="bg-body-tertiary border p-3 rounded small mb-0" style="max-height:320px; overflow:auto;"><?= h($backtrace) ?></pre>
            <?php endif; ?>
        <?php else: ?>
            <p class="mb-0 text-muted">
                <?= __('No error data found. Generally job error data is purged from Redis after 24 hours, however, you can still view the errors in the log files in "/app/tmp/logs".') ?>
            </p>
        <?php endif; ?>
    </div>
</div>
