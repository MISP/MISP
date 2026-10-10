<?php
/**
 * Placeholders for the health checks of a page. server-settings.js fetches
 * each probe's card from ServersController::serverDiagnostic() and swaps it
 * in, a few at a time, so a slow probe never holds the others back.
 *
 * Params:
 *  - probes array ServerHealthProbes probe ids, in display order
 */

App::uses('ServerHealthProbes', 'Tools');

$meta = ServerHealthProbes::probes();
?>
<div class="ss-probes">
    <?php foreach ($probes as $probe): ?>
        <div class="ss-probe" data-ss-probe="<?= h($probe) ?>" data-ss-probe-pending>
            <div class="card shadow-sm mb-4 ss-section">
                <div class="card-header ss-section-header" style="cursor: default;">
                    <span class="ss-section-icon"><i class="fas fa-<?= h($meta[$probe]['icon']) ?>"></i></span>
                    <div class="flex-grow-1 fw-semibold"><?= h($meta[$probe]['title']) ?></div>
                    <span class="text-muted small d-flex align-items-center gap-2">
                        <span class="spinner-border spinner-border-sm" aria-hidden="true"></span><?= __('Checking…') ?>
                    </span>
                </div>
                <div class="card-body d-flex flex-column gap-2" aria-hidden="true">
                    <span class="ss-skeleton" style="width: 85%;"></span>
                    <span class="ss-skeleton" style="width: 60%;"></span>
                    <span class="ss-skeleton" style="width: 72%;"></span>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
</div>
