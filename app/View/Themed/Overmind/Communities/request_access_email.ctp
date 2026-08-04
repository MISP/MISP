<div class="container-fluid mt-4">
    <div class="mb-4">
        <h3 class="fw-bold text-dark">
            <i class="fas fa-paper-plane text-primary me-2"></i>
            <?= __('Email to send in order to request access') ?>
        </h3>
        <?php if (empty($mock)): ?>
        <div class="alert alert-warning border-0 shadow-sm d-flex align-items-center rounded-4" role="alert">
            <i class="fas fa-exclamation-triangle fs-4 me-3"></i>
            <div>
                <?= __('Emailing is currently disabled on the instance, but we have generated the e-mail that would normally be sent out below.') ?>
            </div>
        </div>
        <?php else: ?>
        <div class="alert alert-info border-0 shadow-sm d-flex align-items-center rounded-4" role="alert">
            <i class="fas fa-info-circle fs-4 me-3"></i>
            <div>
                <?= __('Please find a generated e-mail below that you can use to contact the community in question') ?>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <div class="card border-0 shadow-sm rounded-4 overflow-hidden">

        <!-- HEADERS -->
        <div class="card-header bg-light border-bottom p-4">
            <div class="text-muted small text-uppercase fw-bold mb-3">
                <i class="fas fa-list-ul me-1"></i> <?= __('Headers') ?>
            </div>
            <div class="bg-white rounded-3 p-3 border small">
                <?= nl2br(h($result['headers'])) ?>
            </div>
        </div>

        <!-- MESSAGE -->
        <div class="card-body bg-light p-4">
            <div class="d-flex align-items-center justify-content-between mb-3">
                <div class="text-muted small text-uppercase fw-bold">
                    <i class="fas fa-envelope-open-text me-1"></i> <?= __('Message') ?>
                </div>
                <div class="text-end">
                    <button
                        class="btn btn-outline-secondary btn-sm rounded-pill px-3"
                        onclick="copyToClipboard(this, this.dataset.message)"
                        data-message="<?= h($result['message']) ?>"
                        data-bs-toggle="tooltip"
                        title="<?= __('Copy Message Body') ?>">
                        <i class="fas fa-copy me-1"></i> <?= __('Copy Message Body') ?>
                    </button>
                </div>
            </div>
            <div class="bg-white rounded-3 p-3 border small" style="white-space: pre-wrap; line-height: 1.6;">
                <?= h($result['message']) ?>
            </div>
        </div>

    </div>
</div>