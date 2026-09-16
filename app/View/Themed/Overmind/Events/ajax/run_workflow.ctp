<?php

$workflows = $workflows ?? [];
/* runWorkflow() passes only the workflow list, so the id comes from the URL. */
$eventId = $this->request->params['pass'][0] ?? ($id ?? null);

$uid = 'evt-workflow-' . dechex(mt_rand());
$hasWorkflows = !empty($workflows);

echo $this->Form->create('Event', [
    'id' => 'PromptForm',
    'url' => $this->request->here(false),
    'class' => 'm-0',
]);
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'primary',
        'eyebrow' => __('Event'),
        'title' => __('Run ad-hoc workflow'),
        'description' => __('Runs the selected workflows once, with this event as their input.'),
        'titleIcon' => 'fas fa-diagram-project',
        'icon' => 'fas fa-diagram-project',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <?php if (!$hasWorkflows): ?>
            <p class="mb-0 lh-base text-body-secondary">
                <?= __('No ad-hoc workflow is enabled with the trigger data input scope "passed_event_ids", so there is nothing to run.') ?>
            </p>
        <?php else: ?>
            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Workflows'),
                    'badge' => (string)count($workflows),
                ]) ?>

                <div class="border rounded-2 px-3 py-2" id="<?= h($uid) ?>-list"
                     style="max-height:13rem; overflow-y:auto;">
                    <?php foreach ($workflows as $entry): ?>
                        <?php $wf = $entry['Workflow']; ?>
                        <div class="form-check mb-1">
                            <?= $this->Form->checkbox($wf['id'], [
                                'class' => 'form-check-input',
                                'id' => $uid . '-wf-' . (int)$wf['id'],
                            ]) ?>
                            <label class="form-check-label d-flex align-items-center gap-2"
                                   style="font-size:.85rem;"
                                   for="<?= h($uid . '-wf-' . (int)$wf['id']) ?>">
                                <span class="badge bg-secondary-subtle text-secondary-emphasis border border-secondary-subtle"
                                      style="font-size:.65rem;"><?= h($wf['trigger_id']) ?></span>
                                <span class="fw-semibold"><?= h($wf['name']) ?></span>
                            </label>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <div>
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Environment variables'),
                ]) ?>
                <?= $this->Form->textarea('environment_variables', [
                    'class' => 'form-control font-monospace',
                    'rows' => 3,
                    'style' => 'font-size:.8rem;',
                    'placeholder' => '{"key": "value"}',
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('JSON object handed to the workflows as their environment. Left empty, they run with none.'),
                ]) ?>
            </div>
        <?php endif; ?>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'primary',
        'bleed' => true,
        'meta' => $eventId === null ? [] : [['label' => __('Event'), 'id' => $eventId]],
        'cancel' => ['label' => $hasWorkflows ? __('Cancel') : __('Close'), 'icon' => 'fas fa-xmark'],
        'submit' => $hasWorkflows
            ? [
                'label' => __('Run'),
                'icon' => 'fas fa-play',
                'type' => 'submit',
                'id' => $uid . '-submit',
                // running none of them only produces a flash error
                'disabled' => true,
            ]
            : false,
    ]) ?>
</div>
<?= $this->Form->end() ?>

<?php if ($hasWorkflows): ?>
<script>
(function () {
    var list = document.getElementById('<?= $uid ?>-list');
    var submit = document.getElementById('<?= $uid ?>-submit');
    if (!list || !submit) {
        return;
    }
    function syncSubmit() {
        submit.disabled = !list.querySelector('input[type=checkbox]:checked');
    }
    list.addEventListener('change', syncSubmit);
    syncSubmit();
})();
</script>
<?php endif; ?>
