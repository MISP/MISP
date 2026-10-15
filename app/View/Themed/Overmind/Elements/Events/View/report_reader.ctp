<?php
/**
 * The event page's report reader, one modal for every report of the event:
 * event-report-reader.js opens it from the overview card and the Reports tab.
 */
?>
<div class="modal fade eo-reader" id="report-reader-modal" tabindex="-1" aria-labelledby="report-reader-title" aria-hidden="true"
     data-template-variables="<?= h(json_encode($reportTemplateVariables ?? [])) ?>"
     data-text-failed="<?= h(__('The report could not be loaded.')) ?>">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header eo-reader-head">
                <div class="misp-icon-tile eo-tile" style="--tile:var(--bs-report);--tile-bg:color-mix(in srgb, var(--bs-report) 12%, transparent);">
                    <i class="misp-icon misp-icon-report misp-simple"></i>
                </div>
                <div class="min-w-0 me-auto">
                    <h5 class="modal-title eo-reader-title" id="report-reader-title" data-reader-name></h5>
                    <div class="eo-card-sub" data-reader-sub></div>
                </div>
                <a class="btn btn-sm btn-outline-secondary flex-shrink-0" href="#" data-reader-page
                   title="<?= h(__('Open report page')) ?>" aria-label="<?= h(__('Open report page')) ?>">
                    <i class="fas fa-arrow-up-right-from-square"></i><span class="d-none d-sm-inline ms-1"><?= __('Open report page') ?></span>
                </a>
                <button type="button" class="btn-close flex-shrink-0" data-bs-dismiss="modal" aria-label="<?= h(__('Close')) ?>"></button>
            </div>
            <div class="modal-body eo-reader-body">
                <div class="eo-reader-loader" data-reader-loader>
                    <div class="misp-loader" role="status"></div>
                </div>
                <div class="markdown-preview-body eo-report-full" data-reader-body></div>
            </div>
        </div>
    </div>
</div>
