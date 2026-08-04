<?php
/*
 * BS5 post-run summary for /event_templates/update (POST). Mirrors the
 * default-theme `update.ctp` shape with Bootstrap 5 cards, one per
 * outcome category from EventTemplate::updateFromLibrary
 * (PRD §5.3): installed / updated / skipped_current / skipped_forked /
 * failed.
 */
$installed = isset($summary['installed']) ? $summary['installed'] : array();
$updated = isset($summary['updated']) ? $summary['updated'] : array();
$skippedCurrent = isset($summary['skipped_current']) ? $summary['skipped_current'] : array();
$skippedForked = isset($summary['skipped_forked']) ? $summary['skipped_forked'] : array();
$failed = isset($summary['failed']) ? $summary['failed'] : array();

$totalChanged = count($installed) + count($updated);

$renderRows = function ($rows) use ($baseurl) {
    if (empty($rows)) {
        return '<div class="text-muted fst-italic small">' . __('None.') . '</div>';
    }
    $items = '';
    foreach ($rows as $r) {
        $hasId = isset($r['id']) && (int)$r['id'] > 0;
        $name = h($r['name'] ?? '');
        $linkOpen = $hasId
            ? sprintf('<a href="%s">', h($baseurl . '/event_templates/view/' . (int)$r['id']))
            : '';
        $linkClose = $hasId ? '</a>' : '';
        $items .= sprintf(
            '<li class="list-group-item d-flex justify-content-between">'
            . '<span>%s%s%s</span>'
            . '<code class="text-muted">%s</code>'
            . '</li>',
            $linkOpen, $name, $linkClose,
            h($r['slug'] ?? '')
        );
    }
    return '<ul class="list-group list-group-flush">' . $items . '</ul>';
};
?>
<div class="container-fluid mt-3">
    <h2 class="fw-semibold mb-3"><?= __('Library update — Event Templates') ?></h2>

    <?php if ($totalChanged === 0 && empty($failed)): ?>
        <div class="alert alert-info">
            <i class="fas fa-info-circle me-1"></i>
            <?= __('Nothing to do — every library template is already current locally.') ?>
        </div>
    <?php else: ?>
        <p class="text-muted">
            <?= __('Walked the bundled <code>misp-event-templates</code> submodule and reconciled it with this instance. Summary:') ?>
        </p>
    <?php endif; ?>

    <div class="row g-3">
        <div class="col-md-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-success-subtle fw-semibold">
                    <i class="fas fa-plus-circle me-1"></i>
                    <?= __('Installed') ?>
                    <span class="badge bg-success ms-2"><?= count($installed) ?></span>
                </div>
                <?= $renderRows($installed) ?>
                <?php if (!empty($installed)): ?>
                    <div class="card-footer text-muted small">
                        <?= __('New rows are <code>active = 0</code> by default — flip the active flag on each row before your team uses them.') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="col-md-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-primary-subtle fw-semibold">
                    <i class="fas fa-sync me-1"></i>
                    <?= __('Updated') ?>
                    <span class="badge bg-primary ms-2"><?= count($updated) ?></span>
                </div>
                <?= $renderRows($updated) ?>
                <?php if (!empty($updated)): ?>
                    <div class="card-footer text-muted small">
                        <?= __('Existing rows whose upstream content changed. Local id, ownership, and active flag preserved.') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="col-md-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-light fw-semibold">
                    <i class="fas fa-check me-1"></i>
                    <?= __('Already current') ?>
                    <span class="badge bg-secondary ms-2"><?= count($skippedCurrent) ?></span>
                </div>
                <?= $renderRows($skippedCurrent) ?>
            </div>
        </div>

        <div class="col-md-6">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-warning-subtle fw-semibold">
                    <i class="fas fa-code-fork me-1"></i>
                    <?= __('Skipped (forked)') ?>
                    <span class="badge bg-warning text-dark ms-2"><?= count($skippedForked) ?></span>
                </div>
                <?= $renderRows($skippedForked) ?>
                <?php if (!empty($skippedForked)): ?>
                    <div class="card-footer text-muted small">
                        <?= __('Rows where you flipped <code>misp_default</code> off. Library updates leave these alone. Flip the flag back to opt back into upstream updates.') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <?php if (!empty($failed)): ?>
            <div class="col-12">
                <div class="card shadow-sm border-danger">
                    <div class="card-header bg-danger-subtle text-danger fw-semibold">
                        <i class="fas fa-exclamation-triangle me-1"></i>
                        <?= __('Failed') ?>
                        <span class="badge bg-danger ms-2"><?= count($failed) ?></span>
                    </div>
                    <ul class="list-group list-group-flush">
                        <?php foreach ($failed as $f): ?>
                            <li class="list-group-item d-flex justify-content-between">
                                <span><?= h($f['error']) ?></span>
                                <code class="text-muted"><?= h($f['slug'] ?? '(no slug)') ?></code>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <div class="mt-4">
        <a href="<?= h($baseurl . '/event_templates/index') ?>" class="btn btn-primary">
            <i class="fas fa-arrow-left me-1"></i><?= __('Back to event templates') ?>
        </a>
    </div>
</div>
