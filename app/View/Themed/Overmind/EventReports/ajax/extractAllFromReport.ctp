<?php
/*
 * Automatic entity extraction from one report, rendered by
 * EventReportsController::extractAllFromReport() on GET into the main modal.
 * The action answers ajax only, so the form is posted by fetch; the server
 * rewrites the report, hence the reload back onto the Edit Content tab.
 *
 * Set by the controller:
 *   $reportId  int
 */
$reportId = (int)$reportId;
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'report',
        'eyebrow' => __('Extract entities'),
        'title' => __('Automatic extraction'),
        'description' => __('The freetext import tools read the report and turn what they recognise into attributes.'),
        'titleIcon' => 'fas fa-wand-magic-sparkles',
        'icon' => 'fas fa-wand-magic-sparkles',
    ]) ?>

    <?= $this->Form->create('EventReport', [
        'id' => 'ExtractAllForm',
        'url' => $baseurl . '/eventReports/extractAllFromReport/' . $reportId,
        'novalidate' => true,
        'class' => 'm-0',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <p class="mb-0 lh-base">
            <?= __('Every value found in the text becomes an attribute of the event, and each of its occurrences in the report is replaced by a reference to that attribute. Values the event already holds are referenced rather than created again.') ?>
        </p>

        <div>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'report',
                'label' => __('After the extraction'),
            ]) ?>
            <div class="form-check form-switch mb-0">
                <?= $this->Form->checkbox('tag_event', [
                    'class' => 'form-check-input',
                    'role' => 'switch',
                    'id' => 'ExtractAllTagEvent',
                ]) ?>
                <label class="form-check-label" for="ExtractAllTagEvent">
                    <?= __('Tag the event with the contextual elements found in the report') ?>
                </label>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Tags and galaxy clusters named in the text are attached to the event.'),
            ]) ?>
        </div>

        <div class="d-flex gap-2 p-3 rounded-2 bg-warning-subtle text-warning-emphasis border-start border-3 border-warning" role="note">
            <i class="fas fa-triangle-exclamation" style="font-size:.8rem; margin-top:.15rem;"></i>
            <div class="lh-base" style="font-size:.8rem;">
                <?= __('Everything found is created at once. To choose value by value, use Tools › Manual extraction instead.') ?>
            </div>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'report',
        'bleed' => true,
        'meta' => [['label' => __('Report'), 'id' => $reportId]],
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark'],
        'submit' => [
            'label' => __('Extract'),
            'icon' => 'fas fa-wand-magic-sparkles',
            'id' => 'ExtractAllSubmit',
        ],
    ]) ?>

    <?= $this->Form->end() ?>
</div>

<script>
(function () {
    var form = document.getElementById('ExtractAllForm');
    if (!form) { return; }
    var L = <?= json_encode([
        'working' => __('Extracting…'),
        'failed' => __('The extraction failed:'),
        'extract' => __('Extract'),
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    form.addEventListener('submit', function (e) {
        if (e.defaultPrevented) { return; }
        e.preventDefault();
        var button = document.getElementById('ExtractAllSubmit');
        if (button) {
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.working;
        }
        fetch(form.getAttribute('action'), {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            body: new URLSearchParams(new FormData(form))
        }).then(function (r) {
            return r.json();
        }).then(function (result) {
            if (!result.saved) {
                throw new Error(typeof result.errors === 'string' ? result.errors : (result.message || ''));
            }
            showToast(result.message);
            window.location.hash = '#tab-content';
            window.location.reload();
        }).catch(function (error) {
            showToast(L.failed + ' ' + error.message, 'danger');
            if (button) {
                button.disabled = false;
                button.innerHTML = '<i class="fas fa-wand-magic-sparkles me-1"></i>' + L.extract;
            }
        });
    });
}());
</script>
