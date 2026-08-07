<div class="d-flex justify-content-center">
    <div class="card shadow-sm d-inline-block w-auto" style="min-width: 20em;">
        <div class="card-header">
            <h4 class="card-title mb-2 mt-2"><?= __('ZeroMQ server status') ?></h4>
        </div>
        <div class="card-body">
            <?php if (isset($time)): ?>
                <div class="dg-row"><span class="dg-row-label"><?= __('Reply time: ') ?></span>
                    <span class="ms-auto dg-figures"><?= $this->Time->time($time) ?></span></div>
                <div class="dg-row"><span class="dg-row-label"><?= __('Start time: ') ?></span>
                    <span class="ms-auto dg-figures"><?= $this->Time->time($time2) ?></span></div>
                <div class="dg-row"><span class="dg-row-label"><?= __('Events processed: ') ?></span>
                    <span class="ms-auto dg-figures"><?= h($events) ?></span></div>
                <div class="dg-row"><span class="dg-row-label"><?= __('Messages processed: ') ?></span>
                    <span class="ms-auto dg-figures"><?= h($messages) ?></span></div>
            <?php else: ?>
                <div class="alert alert-danger d-flex gap-2 mb-0" role="alert">
                    <i class="fas fa-triangle-exclamation mt-1"></i>
                    <div><?= __('The ZeroMQ server is unreachable.') ?></div>
                </div>
            <?php endif; ?>
            <div class="d-flex justify-content-end mt-3">
                <button type="button" class="btn btn-outline-secondary"
                        onclick="bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();">
                    <?= __('Close') ?>
                </button>
            </div>
        </div>
    </div>
</div>
