<?php
/*
 * GET/POST /objectReferences/bulkAdd/{eventId}/{ids}
 *
 * The attribute index's "Relationship" mass action: one object of the event
 * points at every selected attribute with the same relationship.
 * Variables come from ObjectReferencesController::bulkAdd.
 */
$count = count($selectedAttributes);
$eventId = (int)reset($selectedAttributes)['event_id'];
$idsJson = json_encode(array_map('intval', array_keys($selectedAttributes)));
$defaultRelationship = isset($relationships['related-to']) ? 'related-to' : key($relationships);

$objectPreview = [];
foreach ($eventObjects as $uuid => $object) {
    $objectPreview[$uuid] = [
        'name' => $object['name'],
        'meta' => $object['meta-category'] ?? '',
        'attributes' => array_map(function ($attribute) {
            return [
                'relation' => $attribute['object_relation'] ?? '',
                'value' => $attribute['value'],
            ];
        }, $object['Attribute'] ?? []),
    ];
}

echo $this->Form->create('ObjectReference', [
    'id' => 'objRefBulkForm',
    'url' => '/objectReferences/bulkAdd/' . $eventId . '/' . $idsJson,
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'object',
    'eyebrow' => __n('%s selected attribute', '%s selected attributes', $count, $count),
    'title' => __('Add a relationship'),
    'titleIcon' => 'fas fa-diagram-project',
    'description' => __('One object of the event points at every selected attribute with the same relationship.'),
    'icon' => 'fas fa-diagram-project',
]) ?>

<div class="container-fluid px-4 py-4" id="objRefBulkBody">
    <?php if (empty($validSourceUuid)): ?>
        <div class="text-center text-muted py-4">
            <i class="fas fa-cubes fa-2x mb-2 d-block opacity-50"></i>
            <?= __('This event has no object yet, so there is nothing a relationship could start from.') ?>
        </div>
    <?php else: ?>
    <div class="d-flex flex-column gap-4">

        <div class="row g-4">
            <div class="col-lg-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'object',
                    'label' => __('Source object'),
                    'required' => true,
                    'for' => 'objRefBulkSource',
                ]) ?>
                <?= $this->Form->select('ObjectReference.source_uuid', $validSourceUuid, [
                    'id' => 'objRefBulkSource',
                    'class' => 'form-select tom-select',
                    'empty' => false,
                ]) ?>
                <div class="border rounded mt-2 p-2 small bg-body-tertiary"
                     id="objRefBulkPreview" style="max-height: 12rem; overflow-y: auto;"></div>
            </div>
            <div class="col-lg-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'object',
                    'label' => __('Relationship type'),
                    'required' => true,
                    'for' => 'objRefBulkType',
                ]) ?>
                <?= $this->Form->select('ObjectReference.relationship_type_select', $relationships, [
                    'id' => 'objRefBulkType',
                    'class' => 'form-select tom-select',
                    'empty' => false,
                    'value' => $defaultRelationship,
                ]) ?>
                <?= $this->Form->text('ObjectReference.relationship_type', [
                    'id' => 'objRefBulkCustom',
                    'class' => 'form-control mt-2 d-none',
                    'placeholder' => __('Custom relationship type'),
                    'aria-label' => __('Custom relationship type'),
                ]) ?>

                <div class="mt-3">
                    <?= $this->element('genericElementsBS5/Forms/section_label', [
                        'accent' => 'object',
                        'label' => __('Comment'),
                        'for' => 'objRefBulkComment',
                    ]) ?>
                    <?= $this->Form->textarea('ObjectReference.comment', [
                        'id' => 'objRefBulkComment',
                        'class' => 'form-control',
                        'rows' => 2,
                    ]) ?>
                </div>
            </div>
        </div>

        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __n('Target attribute', 'Target attributes', $count),
            ]) ?>
            <div class="border rounded" style="max-height: 14rem; overflow-y: auto;">
                <table class="table table-sm align-middle mb-0">
                    <tbody>
                        <?php foreach ($selectedAttributes as $attribute): ?>
                            <tr>
                                <td class="text-nowrap" style="width: 1%;">
                                    <span class="badge text-bg-light border font-monospace"><?= h($attribute['type']) ?></span>
                                </td>
                                <td class="font-monospace small text-break"><?= h($attribute['value']) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
    <script type="application/json" id="objRefBulkObjects"><?= json_encode(
        (object)$objectPreview,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
    ) ?></script>
    <?php endif; ?>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'object',
        'submit' => empty($validSourceUuid) ? false : [
            'label' => __n('Add %s relationship', 'Add %s relationships', $count, $count),
            'icon' => 'fas fa-link',
            'id' => 'objRefBulkSubmit',
        ],
    ]) ?>
</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('objRefBulkForm');
    var dataNode = document.getElementById('objRefBulkObjects');
    if (!form || !dataNode) { return; }
    var objects = JSON.parse(dataNode.textContent);
    var source = document.getElementById('objRefBulkSource');
    var type = document.getElementById('objRefBulkType');
    var custom = document.getElementById('objRefBulkCustom');
    var preview = document.getElementById('objRefBulkPreview');
    var submitBtn = document.getElementById('objRefBulkSubmit');

    function renderPreview() {
        var object = objects[source.value];
        preview.textContent = '';
        if (!object) { return; }
        var head = document.createElement('div');
        head.className = 'fw-semibold mb-1';
        head.textContent = object.name + (object.meta ? ' · ' + object.meta : '');
        preview.appendChild(head);
        object.attributes.forEach(function (attribute) {
            var line = document.createElement('div');
            line.className = 'text-truncate';
            var relation = document.createElement('span');
            relation.className = 'text-muted me-1';
            relation.textContent = attribute.relation + ':';
            var value = document.createElement('span');
            value.className = 'font-monospace';
            value.textContent = attribute.value;
            line.appendChild(relation);
            line.appendChild(value);
            preview.appendChild(line);
        });
    }

    function syncCustom() {
        var isCustom = type.value === 'custom';
        custom.classList.toggle('d-none', !isCustom);
        if (isCustom) { custom.focus(); }
    }

    source.addEventListener('change', renderPreview);
    type.addEventListener('change', syncCustom);
    renderPreview();
    syncCustom();

    form.addEventListener('submit', function (e) {
        if (e.defaultPrevented) { return; }
        e.preventDefault();
        if (type.value === 'custom' && custom.value.trim() === '') {
            custom.classList.add('is-invalid');
            custom.focus();
            return;
        }
        custom.classList.remove('is-invalid');
        submitBtn.disabled = true;

        fetch(form.getAttribute('action'), {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            body: new FormData(form)
        })
        .then(function (r) { return r.text(); })
        .then(function (text) {
            var data = JSON.parse(text);
            if (!data.saved) {
                var errors = data.errors && typeof data.errors === 'object'
                    ? Object.values(data.errors).flat().join(' ')
                    : (data.errors || data.message);
                showToast(errors || <?= json_encode(__('The relationships could not be added.')) ?>, 'danger');
                submitBtn.disabled = false;
                return;
            }
            bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();
            showToast(data.message, 'success');
            reloadEventViewIndexTab();
        })
        .catch(function () {
            showToast(<?= json_encode(__('Request failed — please try again.')) ?>, 'danger');
            submitBtn.disabled = false;
        });
    });
}());
</script>
