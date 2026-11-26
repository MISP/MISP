<?php
$isEdit = $this->request->params['action'] === 'editWithTags';

$collection = $this->request->data['TagCollection'] ?? [];
$currentTags = $currentTags ?? [];

echo $this->Form->create('TagCollection', [
    'id' => 'tagCollectionForm',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Tag Collections'),
    'title' => $isEdit ? __('Edit Tag Collection') : __('Add Tag Collection'),
    'description' => __('A collection groups the tags and galaxy clusters that are usually applied together, so they can be attached in one go.'),
    'icon' => 'fas fa-layer-group',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Collection Name') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'TagCollectionName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. Phishing triage set'),
                'autocomplete' => 'off',
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
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('What this set of tags is for…'),
            ]) ?>
        </div>

        <!-- ── TAGS ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-tag fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <i class="fas fa-tags"></i>
                <?= __('Tags') ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/tag_picker_field', [
                'field' => 'TagCollection.tags',
                'uid' => 'tag-collection-tags',
                'categories' => [
                    'all' => [
                        'label' => __('All Tags'),
                        'tags' => $pickerAllTags ?? [],
                    ],
                    'custom' => [
                        'label' => __('Custom Tags'),
                        'tags' => $pickerCustomTags ?? [],
                    ],
                ],
                'selected' => $currentTags,
                'emptyText' => __('No tags in this collection yet.'),
            ]) ?>
        </div>

        <!-- ── GALAXIES ────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-galaxy fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <span class="misp-icon misp-icon-galaxy misp-simple"></span>
                <?= __('Galaxies') ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/galaxy_picker_field', [
                'field' => 'TagCollection.galaxies',
                'uid' => 'tag-collection-galaxies',
                'galaxyList' => $galaxyList ?? [],
                'selected' => $currentClusters ?? [],
                'emptyText' => __('No galaxy clusters in this collection yet.'),
            ]) ?>
        </div>

        <!-- ── VISIBILITY ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Visibility'),
            ]) ?>
            <?php $allOrgs = !empty($collection['all_orgs']); ?>
            <label class="d-flex align-items-center gap-3 rounded-2 p-3 w-100
                          user-select-none mb-0"
                   id="TagCollectionAllOrgsCard"
                   style="cursor:pointer; transition:border-color .15s;
                          border:1px solid <?= $allOrgs ? 'var(--bs-primary)' : '#dee2e6' ?>;">
                <?= $this->Form->checkbox('all_orgs', [
                    'id' => 'TagCollectionAllOrgs',
                    'class' => 'form-check-input flex-shrink-0',
                    'style' => 'margin-top:0;',
                    'checked' => $allOrgs,
                ]) ?>
                <div class="flex-fill">
                    <div class="fw-bold text-uppercase"
                         style="font-size:.72rem; letter-spacing:.06em;
                                line-height:1.2;">
                        <?= __('Visible to all organisations') ?>
                    </div>
                    <div class="text-muted"
                         style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                        <?= __('Left off, only your own organisation sees this collection.') ?>
                    </div>
                </div>
                <i class="fas fa-globe" id="TagCollectionAllOrgsIcon"
                   style="font-size:.95rem; transition:color .15s;
                          color:<?= $allOrgs ? 'var(--bs-primary)' : '#adb5bd' ?>;"></i>
            </label>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($collection['id']) ? [['label' => __('Collection'), 'id' => $collection['id']]] : [],
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Collection')],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var NAME_REQUIRED = <?= json_encode(__('Please provide a name for the collection.')) ?>;

    /* Visibility card follows its checkbox, like the option cards in Tags/add */
    var allOrgsBox = document.getElementById('TagCollectionAllOrgs');
    var allOrgsCard = document.getElementById('TagCollectionAllOrgsCard');
    var allOrgsIcon = document.getElementById('TagCollectionAllOrgsIcon');
    if (allOrgsBox && allOrgsCard) {
        allOrgsBox.addEventListener('change', function () {
            allOrgsCard.style.setProperty('border-color',
                allOrgsBox.checked ? 'var(--bs-primary)' : '#dee2e6');
            if (allOrgsIcon) {
                allOrgsIcon.style.setProperty('color',
                    allOrgsBox.checked ? 'var(--bs-primary)' : '#adb5bd');
            }
        });
    }

    var nameEl = document.getElementById('TagCollectionName');
    var form = document.getElementById('tagCollectionForm');
    if (form && nameEl) {
        var errorId = 'tagCollectionNameError';

        form.addEventListener('submit', function (e) {
            if (nameEl.value.trim()) { return; }
            e.preventDefault();
            e.stopPropagation();
            nameEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
            if (!document.getElementById(errorId)) {
                var msg = document.createElement('div');
                msg.id = errorId;
                msg.className = 'text-danger d-flex align-items-center gap-1';
                msg.style.fontSize = '.75rem';
                msg.style.marginTop = '.35rem';
                var icon = document.createElement('i');
                icon.className = 'fas fa-circle-exclamation';
                msg.appendChild(icon);
                msg.appendChild(document.createTextNode(NAME_REQUIRED));
                nameEl.parentNode.insertBefore(msg, nameEl.nextSibling);
            }
            nameEl.focus();
        });

        nameEl.addEventListener('input', function () {
            if (!nameEl.value.trim()) { return; }
            nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
        });
    }
})();
</script>
