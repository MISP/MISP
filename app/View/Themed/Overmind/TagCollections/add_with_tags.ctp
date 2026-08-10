<?php
$isEdit = $this->request->params['action'] === 'editWithTags';

$collection = $this->request->data['TagCollection'] ?? [];
$currentTags = $currentTags ?? [];

echo $this->Form->create('TagCollection', [
    'id' => 'tagCollectionForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(219,106,71,.06);
            border-bottom:2px solid var(--bs-tag);">
    <div>
        <div class="text-tag text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Tag Collections') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-tag"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Tag Collection') : __('Add Tag Collection') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('A collection groups tags that are usually applied together, so they can be attached in one go.') ?>
        </p>
    </div>
    <i class="fas fa-layer-group text-tag" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-tag fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Collection Name') ?>
                <span class="badge bg-tag"
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
            <div class="text-tag fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Description') ?>
            </div>
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

        <!-- ── VISIBILITY ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-tag fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Visibility') ?>
            </div>
            <?php $allOrgs = !empty($collection['all_orgs']); ?>
            <label class="d-flex align-items-center gap-3 rounded-2 p-3 w-100
                          user-select-none mb-0"
                   id="TagCollectionAllOrgsCard"
                   style="cursor:pointer; transition:border-color .15s;
                          border:1px solid <?= $allOrgs ? '#DB6A47' : '#dee2e6' ?>;">
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
                          color:<?= $allOrgs ? '#DB6A47' : '#adb5bd' ?>;"></i>
            </label>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($collection['id'])): ?>
                <?= __('Collection') ?>:
                <strong class="text-body">#<?= h($collection['id']) ?></strong>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Collection')),
                [
                    'class' => 'btn btn-tag btn-sm text-white',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

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
            allOrgsCard.style.borderColor = allOrgsBox.checked ? '#DB6A47' : '#dee2e6';
            if (allOrgsIcon) {
                allOrgsIcon.style.color = allOrgsBox.checked ? '#DB6A47' : '#adb5bd';
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
