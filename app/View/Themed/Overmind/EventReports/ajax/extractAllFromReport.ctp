<?php
/*
 * Automatic entity extraction, rendered by
 * EventReportsController::extractAllFromReport() on GET into the main modal.
 * The form is posted by fetch, since the action only answers AJAX; on success
 * the report editor takes the rewritten content through misp:report-saved.
 *
 * Set by the controller:
 *   $reportId  int  the report
 */
$reportId = (int)$reportId;
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'eyebrow' => __('Extract entities'),
        'title' => __('Automatic extraction'),
        'description' => __('Event report #%s', $reportId),
        'titleIcon' => 'fas fa-wand-magic-sparkles',
        'icon' => 'fas fa-wand-magic-sparkles',
    ]) ?>

    <?= $this->Form->create('EventReport', [
        'id' => 'er-auto-extract-form',
        'url' => $baseurl . '/eventReports/extractAllFromReport/' . $reportId,
        'class' => 'm-0',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <p class="mb-0 lh-base">
            <?= __('Every value the freetext import recognises in the report is turned into an attribute of the event, and its occurrences into references to it. Values of the event\'s attributes are linked to them, and tag and galaxy names become tags.') ?>
        </p>

        <div class="form-check form-switch mb-0">
            <?= $this->Form->input('tag_event', [
                'type' => 'checkbox',
                'div' => false,
                'label' => false,
                'class' => 'form-check-input',
                'id' => 'EventReportTagEvent',
            ]) ?>
            <label class="form-check-label" for="EventReportTagEvent">
                <?= __('Also tag the event with the tags and galaxies found in the report') ?>
            </label>
        </div>

        <div class="d-flex gap-2 p-3 rounded-2 bg-warning-subtle text-warning-emphasis border-start border-3 border-warning"
             role="note">
            <i class="fas fa-triangle-exclamation" style="font-size:.8rem; margin-top:.15rem;"></i>
            <div class="lh-base" style="font-size:.8rem;">
                <?= __('The report is rewritten at once, with no review step. Use Manual extraction to pick the values one by one.') ?>
            </div>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'bleed' => true,
        'align' => 'end',
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark'],
        'submit' => [
            'label' => __('Extract all'),
            'icon' => 'fas fa-wand-magic-sparkles',
            'type' => 'submit',
        ],
    ]) ?>

    <?= $this->Form->end() ?>
</div>

<script>
(function () {
    var form = document.getElementById('er-auto-extract-form');
    if (!form) { return; }
    var reportId = <?= json_encode($reportId) ?>;
    var L = <?= json_encode([
        'working' => __('Extracting…'),
        'failed' => __('The automatic extraction failed'),
    ], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    form.addEventListener('submit', async function (e) {
        e.preventDefault();
        var button = form.querySelector('[type="submit"]');
        var label = button ? button.innerHTML : '';
        if (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.working;
        }
        try {
            var response = await fetch(form.getAttribute('action'), {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                body: new URLSearchParams(new FormData(form))
            });
            var data = await response.json().catch(function () { return {}; });
            if (!response.ok || data.saved === false || !data.data || !data.data.report) {
                throw new Error(typeof data.errors === 'string' ? data.errors : (data.message || response.statusText));
            }
            var modal = bootstrap.Modal.getInstance(document.getElementById('mainModal'));
            if (modal) { modal.hide(); }
            showToast(data.message, 'success');
            document.dispatchEvent(new CustomEvent('misp:report-saved', {
                detail: {
                    reportId: reportId,
                    content: data.data.report.EventReport.content,
                    source: 'extraction',
                    elementsChanged: true
                }
            }));
        } catch (err) {
            showToast(L.failed + ': ' + err.message, 'danger');
            if (button) {
                button.disabled = false;
                button.innerHTML = label;
            }
        }
    });
})();
</script>
