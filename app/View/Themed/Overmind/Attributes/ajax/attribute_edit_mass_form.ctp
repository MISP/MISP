<?php
/*
 * GET /attributes/getMassEditForm/{eventId}/{ids} → POST /attributes/editSelected/{eventId}
 *
 * The attribute index's "Edit" mass action. Every field starts on "Keep
 * current", which is the value editSelected() reads as "leave it alone"
 * (2 for the two flags, 6 for distribution, an empty comment).
 * Variables come from AttributesController::__overmindMassEditForm.
 */
$count = count($selectedAttributeIds);
$keepCard = [
    'value' => 2,
    'title' => __('Keep current'),
    'sub' => __('Each one keeps its own'),
    'icon' => 'fas fa-equals',
    'tone' => '#6c757d',
    'toneBg' => 'rgba(108, 117, 125, .12)',
];
if (empty($sharingGroups)) {
    unset($distributionLevels[4]);
}

echo $this->Form->create('Attribute', [
    'id' => 'attrMassEditForm',
    'url' => '/attributes/editSelected/' . $eventId,
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'attribute',
    'eyebrow' => __n('%s selected attribute', '%s selected attributes', $count, $count),
    'title' => __('Edit selected attributes'),
    'titleIcon' => 'fas fa-pen-to-square',
    'description' => __('Only what you change here is written; anything left on "Keep current" stays as it is on each attribute.'),
    'icon' => 'fas fa-layer-group',
]) ?>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <div class="row g-4">
            <div class="col-lg-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'attribute',
                    'label' => __('IDS flag'),
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/choice_cards', [
                    'field' => 'Attribute.to_ids',
                    'accent' => 'attribute',
                    'ariaLabel' => __('IDS flag'),
                    'options' => [
                        $keepCard,
                        ['value' => 1, 'title' => __('Set'), 'sub' => __('Usable for detection'), 'icon' => 'fas fa-check'],
                        ['value' => 0, 'title' => __('Unset'), 'sub' => __('Context only'), 'icon' => 'fas fa-xmark'],
                    ],
                ]) ?>
            </div>
            <div class="col-lg-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'attribute',
                    'label' => __('Correlation'),
                ]) ?>
                <?= $this->element('genericElementsBS5/Forms/choice_cards', [
                    'field' => 'Attribute.disable_correlation',
                    'accent' => 'attribute',
                    'ariaLabel' => __('Correlation'),
                    'options' => [
                        $keepCard,
                        ['value' => 0, 'title' => __('Enable'), 'sub' => __('Correlates with other events'), 'icon' => 'fas fa-link'],
                        ['value' => 1, 'title' => __('Disable'), 'sub' => __('Kept out of correlation'), 'icon' => 'fas fa-link-slash'],
                    ],
                ]) ?>
            </div>
        </div>

        <?= $this->element('genericElementsBS5/Forms/distribution_field', [
            'field' => 'Attribute.distribution',
            'levels' => $distributionLevels,
            'keep' => 6,
            'accent' => 'attribute',
            'compact' => true,
            'sharingGroups' => $sharingGroups,
        ]) ?>

        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'attribute',
                'label' => __('Comment'),
                'for' => 'attrMassEditComment',
            ]) ?>
            <?= $this->Form->textarea('Attribute.comment', [
                'id' => 'attrMassEditComment',
                'class' => 'form-control',
                'rows' => 2,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Replaces the comment of every selected attribute. Leave it empty to keep theirs.'),
            ]) ?>
        </div>


    </div>

    <?php
    // editSelected() reads every key, so the ones this form never changes still travel.
    echo $this->Form->hidden('Attribute.attribute_ids', ['value' => json_encode($selectedAttributeIds)]);
    echo $this->Form->hidden('Attribute.tags_ids_add', ['value' => '[]']);
    echo $this->Form->hidden('Attribute.clusters_ids_add', ['value' => '[]']);
    echo $this->Form->hidden('Attribute.is_proposal', ['value' => 0]);
    // Tags and clusters are the Tag and Cluster actions of the same toolbar.
    echo $this->Form->hidden('Attribute.tags_ids_remove', ['value' => '[]']);
    echo $this->Form->hidden('Attribute.clusters_ids_remove', ['value' => '[]']);
    ?>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'attribute',
        'hint' => __('The event is unpublished once the changes are saved.'),
        'submit' => [
            'label' => __n('Apply to %s attribute', 'Apply to %s attributes', $count, $count),
            'icon' => 'fas fa-check',
            'id' => 'attrMassEditSubmit',
        ],
    ]) ?>
</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('attrMassEditForm');
    if (!form) { return; }
    var submitBtn = document.getElementById('attrMassEditSubmit');

    form.addEventListener('submit', function (e) {
        if (e.defaultPrevented) { return; }
        e.preventDefault();
        submitBtn.disabled = true;

        fetch(form.getAttribute('action'), {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            body: new FormData(form)
        })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (!data.saved) {
                var errors = data.validationErrors
                    ? Object.values(data.validationErrors).flat().join(' ')
                    : (data.errors || <?= json_encode(__('The attributes could not be updated.')) ?>);
                showToast(errors, 'danger');
                submitBtn.disabled = false;
                return;
            }
            bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();
            showToast(<?= json_encode(__n('%s attribute updated.', '%s attributes updated.', $count, $count)) ?>, 'success');
            reloadEventViewIndexTab();
        })
        .catch(function () {
            showToast(<?= json_encode(__('Request failed — please try again.')) ?>, 'danger');
            submitBtn.disabled = false;
        });
    });
}());
</script>
