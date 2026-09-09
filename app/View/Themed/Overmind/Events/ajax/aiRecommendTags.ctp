<?php
/*
 * AI tag recommendations for an event, rendered by
 * EventsController::aiRecommendTags() on GET into the main modal. One row
 * per suggested tag with a checkbox; the accepted names are POSTed back to
 * the same URL as a JSON list in the form's `tags` field, then the tags and
 * galaxies cards of the event view are reloaded and the counts shown as a
 * toast.
 *
 * Set by the controller:
 *   $event      array        the event (id, info)
 *   $rows       array        Event::classifyAiTagSuggestions() rows
 *   $local      bool         the tags will be attached as local tags
 *   $error      string|null  the module's error, when the query failed
 *   $canCreate  bool         the user may create unknown tags
 */
$eventId = (int)$event['Event']['id'];
$selectable = 0;
$needsEditor = false;
foreach ($rows as $row) {
    if ($row['selectable']) {
        $selectable++;
    }
    if ($row['status'] === Event::AI_TAG_NEEDS_TAG_EDITOR) {
        $needsEditor = true;
    }
}
$canSubmit = $error === null && $selectable > 0;
?>
<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('AI actions'),
    'title' => __('Recommend tags'),
    'titleIcon' => 'fas fa-robot',
    'icon' => 'fas fa-tags',
    'description' => __('The AI module suggested these tags for event #%s. Tick the ones to attach.', $eventId),
    'close' => true,
]) ?>

<div class="p-4" style="background:var(--bs-tertiary-bg, #f8f9fa);">
    <?php if ($local): ?>
        <div class="alert alert-info py-2 small mb-3">
            <i class="fas fa-user me-1"></i><?= __('You cannot modify this event: the accepted tags are attached as local tags.') ?>
        </div>
    <?php endif; ?>
    <?php if ($needsEditor): ?>
        <div class="alert alert-warning py-2 small mb-3">
            <i class="fas fa-circle-info me-1"></i><?= __('Some suggestions are tags unknown to this instance. Creating them needs the tag editor permission, so they cannot be selected.') ?>
        </div>
    <?php endif; ?>

    <?php if ($error !== null): ?>
        <div class="alert alert-danger mb-0"><i class="fas fa-triangle-exclamation me-1"></i><?= h($error) ?></div>
    <?php elseif (empty($rows)): ?>
        <div class="p-4 text-center text-muted"><i class="fas fa-inbox me-1"></i><?= __('The module suggested no tags for this event.') ?></div>
    <?php else: ?>
        <?php
        echo $this->Form->create('Event', [
            'url' => $baseurl . '/events/aiRecommendTags/' . $eventId,
            'id' => 'aiRecommendTagsForm',
        ]);
        // A text input rather than a hidden one: the form token locks the
        // value of a hidden field, and this one is filled on submit.
        echo $this->Form->input('tags', [
            'label' => false,
            'div' => false,
            'type' => 'text',
            'id' => 'aiRecommendTagsField',
            'value' => '',
            'style' => 'display:none;',
        ]);
        echo $this->Form->end();
        ?>

        <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
            <div class="form-check mb-0">
                <input type="checkbox" class="form-check-input" id="aiRecommendTagsCheckAll" <?= $selectable ? 'checked' : 'disabled' ?>>
                <label class="form-check-label small" for="aiRecommendTagsCheckAll"><?= __('Select all') ?></label>
            </div>
            <span class="text-muted small ms-auto">
                <span id="aiRecommendTagsSelCount"><?= $selectable ?></span> / <?= $selectable ?> <?= __('selected') ?>
            </span>
        </div>

        <div class="card border-0 shadow-sm">
            <div style="max-height:55vh; overflow-y:auto;">
                <table class="table table-sm table-hover align-middle mb-0" id="aiRecommendTagsTable">
                    <thead class="table-light" style="position:sticky; top:0; z-index:1;">
                        <tr>
                            <th style="width:2.2rem;"></th>
                            <th><?= __('Tag') ?></th>
                            <th><?= __('Status') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($rows as $row): ?>
                        <tr class="<?= $row['selectable'] ? '' : 'text-muted' ?>">
                            <td>
                                <input type="checkbox" class="form-check-input aiRecommendTagCheck"
                                    data-name="<?= h($row['name']) ?>"
                                    <?= $row['selectable'] ? 'checked' : 'disabled' ?>
                                    aria-label="<?= h($row['name']) ?>">
                            </td>
                            <td>
                                <?= $this->element('genericElementsBS5/Badges/tag', [
                                    'tag' => ['name' => $row['name'], 'colour' => $row['colour']],
                                    'local' => $local,
                                    'hiddenClass' => '',
                                    'showFavourite' => false,
                                ]) ?>
                            </td>
                            <td class="small">
                                <?php if ($row['is_galaxy']): ?>
                                    <span class="badge text-bg-light border me-1"><i class="fas fa-atlas me-1"></i><?= __('galaxy cluster') ?></span>
                                <?php endif; ?>
                                <?php if (!$row['exists'] && $row['status'] !== Event::AI_TAG_PRESENT): ?>
                                    <span class="badge text-bg-info me-1"><?= __('new') ?></span>
                                <?php endif; ?>
                                <?php if ($row['reason'] !== ''): ?>
                                    <span class="text-muted"><?= h($row['reason']) ?></span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endif; ?>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'primary',
        'meta' => [['label' => __('Event'), 'id' => $eventId]],
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark', 'attrs' => ['data-bs-dismiss' => 'modal']],
        'submit' => $canSubmit ? [
            'label' => __('Attach selected tags'),
            'icon' => 'fas fa-tags',
            'id' => 'aiRecommendTagsSubmit',
            'type' => 'button',
        ] : false,
    ]) ?>
</div>

<script>
    var EVENT_ID = <?= $eventId ?>;
    var form = document.getElementById('aiRecommendTagsForm');
    var table = document.getElementById('aiRecommendTagsTable');
    var submitBtn = document.getElementById('aiRecommendTagsSubmit');
    var checkAll = document.getElementById('aiRecommendTagsCheckAll');
    var selCount = document.getElementById('aiRecommendTagsSelCount');
    var checks = table ? Array.prototype.slice.call(table.querySelectorAll('.aiRecommendTagCheck:not(:disabled)')) : [];

    if (form) { form.addEventListener('submit', function (e) { e.preventDefault(); }); }

    function refreshCount() {
        var n = checks.filter(function (c) { return c.checked; }).length;
        if (selCount) { selCount.textContent = n; }
        if (submitBtn) { submitBtn.disabled = (n === 0); }
        if (checkAll) { checkAll.checked = (checks.length > 0 && n === checks.length); }
    }
    checks.forEach(function (c) { c.addEventListener('change', refreshCount); });
    if (checkAll) {
        checkAll.addEventListener('change', function () {
            checks.forEach(function (c) { c.checked = checkAll.checked; });
            refreshCount();
        });
    }
    refreshCount();

    function reloadCards() {
        ['reloadTagsCard_evt-tags-', 'reloadGalaxiesCard_evt-galaxies-'].forEach(function (hook) {
            var fn = window[hook + EVENT_ID];
            if (typeof fn === 'function') { fn(); }
        });
    }

    if (submitBtn && form) {
        submitBtn.addEventListener('click', function () {
            var names = checks.filter(function (c) { return c.checked; }).map(function (c) { return c.getAttribute('data-name'); });
            if (names.length === 0) { return; }
            document.getElementById('aiRecommendTagsField').value = JSON.stringify(names);
            submitBtn.disabled = true;
            fetch(form.getAttribute('action'), {
                method: 'POST',
                body: new FormData(form),
                headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var modal = document.getElementById('mainModal');
                if (modal) {
                    (bootstrap.Modal.getInstance(modal) || new bootstrap.Modal(modal)).hide();
                }
                var message = data.success || data.message || data.errors || <?= json_encode(__('The tags could not be attached.')) ?>;
                showToast(message, data.saved ? 'success' : 'danger');
                if (data.attached > 0) { reloadCards(); }
            })
            .catch(function () {
                showToast(<?= json_encode(__('Request failed, please try again.')) ?>, 'danger');
                submitBtn.disabled = false;
            });
        });
    }
</script>
