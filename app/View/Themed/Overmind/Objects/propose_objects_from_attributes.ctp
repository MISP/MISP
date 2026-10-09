<?php
/*
 * GET /objects/proposeObjectsFromAttributes/{eventId}/{ids}
 *
 * The attribute index's "Object" mass action, step one: the object templates
 * the selected types fit in. Picking one swaps the modal body for the add-object
 * form, prefilled with the selection (objects/add/{eventId}/{templateId}?group=).
 * Variables come from ObjectsController::proposeObjectsFromAttributes.
 */
$count = count($selectedAttributeIds);
$addBase = $baseurl . '/objects/add/' . (int)$event_id . '/';
$groupQuery = '?group=' . implode(',', array_map('intval', $selectedAttributeIds));

$compatible = [];
$incompatible = [];
foreach ($potential_templates as $potential) {
    if ($potential['ObjectTemplate']['compatibility'] === true) {
        $compatible[] = $potential['ObjectTemplate'];
    } else {
        $incompatible[] = $potential['ObjectTemplate'];
    }
}
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'object',
    'eyebrow' => __n('%s selected attribute', '%s selected attributes', $count, $count),
    'title' => __('Group into an object'),
    'titleIcon' => 'fas fa-object-group',
    'description' => __('Pick the template the selection becomes. The object form opens with the attributes filled in.'),
    'icon' => 'misp-icon misp-icon-object misp-simple',
]) ?>

<div class="container-fluid px-4 py-4" id="objProposeBody">
    <div class="d-flex flex-column gap-4">

        <?php if (!empty($selected_types)): ?>
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Selected types'),
            ]) ?>
            <div class="d-flex flex-wrap gap-1">
                <?php foreach ($selected_types as $type): ?>
                    <span class="badge text-bg-light border font-monospace"><?= h($type) ?></span>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        <?php if (empty($potential_templates)): ?>
            <div class="text-center text-muted py-4">
                <i class="fas fa-object-ungroup fa-2x mb-2 d-block opacity-50"></i>
                <?= __('No object template matches the selected attributes. Only attributes that are not already in an object can be grouped.') ?>
            </div>
        <?php else: ?>
        <div class="w-100">
            <div class="d-flex align-items-end justify-content-between gap-3 mb-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'object',
                    'label' => __('Templates'),
                ]) ?>
                <input type="search" class="form-control form-control-sm w-auto"
                       id="objProposeFilter"
                       placeholder="<?= __('Filter templates…') ?>"
                       aria-label="<?= __('Filter templates') ?>">
            </div>

            <div class="list-group" style="max-height: 55vh; overflow-y: auto;">
                <?php foreach ($compatible as $template): ?>
                    <button type="button"
                            class="list-group-item list-group-item-action d-flex align-items-start gap-3 obj-propose-row"
                            data-name="<?= h(strtolower($template['name'] . ' ' . $template['meta-category'])) ?>"
                            data-url="<?= h($addBase . (int)$template['id'] . $groupQuery) ?>">
                        <i class="fas fa-circle-check text-success mt-1" title="<?= __('These attributes fit this template') ?>"></i>
                        <div class="flex-grow-1 min-w-0">
                            <div class="fw-semibold">
                                <?= h($template['name']) ?>
                                <span class="text-muted small fw-normal ms-1"><?= h($template['meta-category']) ?></span>
                            </div>
                            <div class="small text-muted text-truncate" title="<?= h($template['description']) ?>">
                                <?= h($template['description']) ?>
                            </div>
                            <?php if (!empty($template['invalidTypes'])): ?>
                                <div class="d-flex flex-wrap gap-1 mt-1 align-items-center">
                                    <span class="small text-muted"><?= __('Ignored:') ?></span>
                                    <?php foreach ($template['invalidTypes'] as $type): ?>
                                        <span class="badge text-bg-warning font-monospace"
                                              title="<?= __('This type has no place in the template: these attributes stay out of the object.') ?>"><?= h($type) ?></span>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                        <i class="fas fa-chevron-right text-muted mt-1"></i>
                    </button>
                <?php endforeach; ?>

                <?php foreach ($incompatible as $template): ?>
                    <div class="list-group-item d-flex align-items-start gap-3 bg-body-tertiary obj-propose-row"
                         data-name="<?= h(strtolower($template['name'] . ' ' . $template['meta-category'])) ?>">
                        <i class="fas fa-ban text-muted mt-1" title="<?= __('These attributes do not fit this template') ?>"></i>
                        <div class="flex-grow-1 min-w-0 opacity-75">
                            <div class="fw-semibold">
                                <?= h($template['name']) ?>
                                <span class="text-muted small fw-normal ms-1"><?= h($template['meta-category']) ?></span>
                            </div>
                            <div class="d-flex flex-wrap gap-1 mt-1 align-items-center">
                                <?php if (!empty($template['compatibility'])): ?>
                                    <span class="small text-muted"><?= __('Missing:') ?></span>
                                    <?php foreach ($template['compatibility'] as $type): ?>
                                        <span class="badge text-bg-danger font-monospace"
                                              title="<?= __('Add an attribute of this type to the selection to use this template.') ?>"><?= h($type) ?></span>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                                <?php if (!empty($template['invalidTypesMultiple'])): ?>
                                    <span class="small text-muted ms-1"><?= __('Only one allowed:') ?></span>
                                    <?php foreach ($template['invalidTypesMultiple'] as $type): ?>
                                        <span class="badge text-bg-secondary font-monospace"
                                              title="<?= __('This template takes a single attribute of this type: keep only one in the selection.') ?>"><?= h($type) ?></span>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            <div class="text-muted small fst-italic mt-2 d-none" id="objProposeNoMatch">
                <?= __('No template matches this filter.') ?>
            </div>
        </div>
        <?php endif; ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'object',
        'hint' => __n(
            '%s template fits the selection.',
            '%s templates fit the selection.',
            count($compatible), count($compatible)
        ),
        'submit' => false,
    ]) ?>
</div>

<script>
(function () {
    var body = document.getElementById('objProposeBody');
    if (!body) { return; }

    body.querySelectorAll('button.obj-propose-row').forEach(function (row) {
        row.addEventListener('click', function () {
            openModal(row.dataset.url, 'xl');
        });
    });

    var filter = document.getElementById('objProposeFilter');
    var noMatch = document.getElementById('objProposeNoMatch');
    if (filter) {
        filter.addEventListener('input', function () {
            var term = filter.value.trim().toLowerCase();
            var shown = 0;
            body.querySelectorAll('.obj-propose-row').forEach(function (row) {
                var hit = term === '' || row.dataset.name.indexOf(term) !== -1;
                row.classList.toggle('d-none', !hit);
                shown += hit ? 1 : 0;
            });
            noMatch.classList.toggle('d-none', shown > 0);
        });
    }
}());
</script>
