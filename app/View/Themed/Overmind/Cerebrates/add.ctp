<?php
$isEdit = $this->request->params['action'] === 'edit';

$cerebrate = $this->request->data['Cerebrate'] ?? [];

$options = [
    [
        'field' => 'pull_orgs', 'id' => 'CerebratePullOrgs',
        'label' => __('Pull organisations'),
        'hint' => __('Fetch the organisations this Cerebrate knows'),
        'icon' => 'fas fa-building',
        // Pulled toward the ink to hold 3:1 on tinted surfaces; the
        // identical fallbacks leave the theme default on #1892B1.
        'accent' => 'color-mix(in srgb, var(--misp-tone-cyan-solid, #1892B1) 85%,'
            . ' var(--misp-ink, #1892B1))',
    ],
    [
        'field' => 'pull_sharing_groups', 'id' => 'CerebratePullSharingGroups',
        'label' => __('Pull sharing groups'),
        'hint' => __('Fetch the sharing groups it publishes'),
        'icon' => 'misp-icon misp-icon-sharing-group misp-simple',
        'accent' => 'var(--misp-tone-blue-solid, #0d6efd)',
    ],
    [
        'field' => 'skip_proxy', 'id' => 'CerebrateSkipProxy',
        'label' => __('Skip proxy'),
        'hint' => __('Reach it directly, ignoring the configured proxy'),
        'icon' => 'fas fa-diagram-project',
        'accent' => 'var(--misp-tone-gray-solid, #6c757d)',
    ],
];

echo $this->Form->create('Cerebrate', [
    'id' => 'cerebrateForm',
    'novalidate' => true,
    'data-required-guard' => true,
]);

$fieldError = function ($field) {
    return $this->Form->error($field, null, ['class' => 'ov-field-error']);
};
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('Cerebrates'),
    'title' => $isEdit ? __('Edit Cerebrate') : __('Add Cerebrate'),
    'description' => __('A Cerebrate node this instance queries for organisation and sharing-group metadata.'),
    'icon' => 'fas fa-network-wired',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Name'),
                'required' => true,
                'for' => 'CerebrateName',
            ]) ?>
            <?= $this->Form->text('name', [
                'id' => 'CerebrateName',
                'class' => 'ov-form-line fs-5',
                'placeholder' => __('e.g. Community Cerebrate'),
                'autocomplete' => 'off',
                'required' => true,
                'data-required-msg' => __('Please provide a name for the node.'),
                'error' => false,
            ]) ?>
            <?= $fieldError('name') ?>
        </div>

        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Connection'),
                'required' => true,
            ]) ?>

            <label class="form-label text-muted mb-1 small" for="CerebrateUrl">
                <?= __('Base URL') ?>
            </label>
            <div class="input-group">
                <span class="input-group-text bg-transparent">
                    <i class="fas fa-link text-muted small"></i>
                </span>
                <?= $this->Form->text('url', [
                    'id' => 'CerebrateUrl',
                    'class' => 'form-control font-monospace',
                    'placeholder' => 'https://cerebrate.example.org',
                    'autocomplete' => 'off',
                    'required' => true,
                    'data-required-msg' => __('Please provide the base URL of the node.'),
                    'error' => false,
                ]) ?>
            </div>
            <?= $fieldError('url') ?>

            <label class="form-label text-muted mb-1 mt-3 small" for="CerebrateAuthkey">
                <?= __('Authentication key') ?>
            </label>
            <div class="input-group">
                <span class="input-group-text bg-transparent">
                    <i class="fas fa-key text-muted small"></i>
                </span>
                <?= $this->Form->text('authkey', [
                    'id' => 'CerebrateAuthkey',
                    'type' => 'password',
                    'class' => 'form-control font-monospace',
                    'placeholder' => __('The API key of a Cerebrate user'),
                    'autocomplete' => 'new-password',
                ]) ?>
                <button type="button" class="btn btn-outline-secondary"
                        onclick="toggleSecret('CerebrateAuthkey', this)"
                        title="<?= __('Show or hide the key') ?>">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Used for every request this instance makes to the node.'),
            ]) ?>
        </div>

        <!-- ── OWNER ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Owner Organisation'),
            ]) ?>
            <?= $this->Form->select('org_id', $dropdownData['org_id'] ?? [], [
                'id' => 'CerebrateOrgId',
                'class' => 'form-select tom-select',
                'empty' => false,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('The organisation this node is attributed to locally.'),
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'rows' => 2,
                'placeholder' => __('What this node is used for…'),
            ]) ?>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Options'),
            ]) ?>
            <div class="row g-2">
                <?php foreach ($options as $option): ?>
                    <div class="col-md-4">
                        <label class="d-flex align-items-center gap-3 rounded-2 p-3
                                      h-100 w-100 user-select-none mb-0"
                               data-option-card
                               data-accent="<?= h($option['accent']) ?>"
                               style="cursor:pointer; transition:border-color .15s;
                                      border:1px solid var(--misp-check-off-line, #dee2e6);">
                            <?= $this->Form->checkbox($option['field'], [
                                'id' => $option['id'],
                                'class' => 'form-check-input flex-shrink-0',
                                'style' => 'margin-top:0;',
                            ]) ?>
                            <div class="flex-fill">
                                <div class="fw-bold text-uppercase"
                                     style="font-size:.72rem; letter-spacing:.06em;
                                            line-height:1.2;">
                                    <?= h($option['label']) ?>
                                </div>
                                <div class="text-muted"
                                     style="font-size:.74rem; margin-top:.2rem;
                                            line-height:1.3;">
                                    <?= h($option['hint']) ?>
                                </div>
                            </div>
                            <i class="<?= h($option['icon']) ?>" data-option-icon
                               style="font-size:.95rem; transition:color .15s;
                                      color:var(--misp-check-off-icon, #adb5bd);"></i>
                        </label>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'primary',
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('Cerebrate'), 'id' => $id]] : [],
        'hint' => __('Organisations and sharing groups are previewed before anything is pulled.'),
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Cerebrate')],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    /* Option cards take their accent from the card itself */
    function paintCard(card) {
        var box = card.querySelector('input[type="checkbox"]');
        var icon = card.querySelector('[data-option-icon]');
        var accent = card.dataset.accent || 'var(--misp-tone-blue-solid, #0d6efd)';
        if (!box) { return; }
        card.style.borderColor = box.checked ? accent : 'var(--misp-check-off-line, #dee2e6)';
        if (icon) { icon.style.color = box.checked ? accent : 'var(--misp-check-off-icon, #adb5bd)'; }
    }
    document.querySelectorAll('[data-option-card]').forEach(function (card) {
        var box = card.querySelector('input[type="checkbox"]');
        if (box) { box.addEventListener('change', function () { paintCard(card); }); }
        paintCard(card);
    });
})();
</script>
