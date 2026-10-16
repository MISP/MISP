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
        <div class="modal-content border-0">
            <?= $this->element('genericElementsBS5/Forms/modal_header', [
                'accent' => 'report',
                'eyebrow' => h(__('Event Reports')),
                'title' => '',
                'titleId' => 'report-reader-title',
                'titleIcon' => 'fas fa-book-open',
                'titleBadge' => '<span class="eo-reader-title" data-reader-name></span>',
                'description' => '<span data-reader-sub></span>',
                'icon' => 'misp-icon misp-icon-report misp-simple',
                'escape' => false,
            ]) ?>
            <div class="modal-body px-4 eo-reader-body">
                <div class="eo-reader-loader" data-reader-loader>
                    <div class="misp-loader" role="status"></div>
                </div>
                <div class="markdown-preview-body eo-report-full" data-reader-body></div>
            </div>
            <?= $this->element('genericElementsBS5/Forms/modal_footer', [
                'accent' => 'report',
                'bleed' => true,
                'metaHtml' => sprintf(
                    '<span>%s: <strong class="text-body" data-reader-id></strong></span>'
                    . '<span class="opacity-50">|</span>'
                    . '<span>%s: <strong class="text-body" data-reader-event></strong></span>',
                    h(__('Report')),
                    h(__('Event'))
                ),
                'cancel' => ['label' => __('Close')],
                'submit' => [
                    'label' => __('Open report page'),
                    'icon' => 'fas fa-arrow-up-right-from-square',
                    'href' => '#',
                    'attrs' => ['data-reader-page' => ''],
                ],
            ]) ?>
        </div>
    </div>
</div>
