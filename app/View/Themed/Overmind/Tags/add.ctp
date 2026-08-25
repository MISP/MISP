<?php
$isEdit = $this->request->params['action'] === 'edit';

$tag = $this->request->data['Tag'] ?? [];

/* Suggested colours for a new tag — the swatch would otherwise open on black
 * and every tag created without touching it would come out black. */
$paletteSuggestions = [
    '#DB6A47', '#1892B1', '#4DA167', '#8B5CF6', '#E67F0D', '#EF476F',
    '#06D6A0', '#8F2D56', '#524948', '#0d6efd', '#b45309', '#0f5132',
];
$currentColour = !empty($tag['colour'])
    ? $tag['colour']
    : $paletteSuggestions[array_rand($paletteSuggestions)];

$orgValue  = $isEdit ? (int)($tag['org_id'] ?? 0) : 0;
$userValue = $isEdit ? (int)($tag['user_id'] ?? 0) : 0;

/* Explicit in both modes: 'checked' => true unconditionally would re-check
 * exportable on a tag that is stored as not exportable. */
$options = [
    'exportable' => [
        'label' => __('Exportable'),
        'hint'  => __('Included when data leaves this instance'),
        'icon'  => 'fas fa-share-nodes',
        'accent' => '#DB6A47',
        'checked' => $isEdit ? !empty($tag['exportable']) : true,
    ],
    'hide_tag' => [
        'label' => __('Hidden'),
        'hint'  => __('Kept out of the tag pickers'),
        'icon'  => 'fas fa-eye-slash',
        'accent' => '#6c757d',
        'checked' => !empty($tag['hide_tag']),
    ],
    'local_only' => [
        'label' => __('Local only'),
        'hint'  => __('Can only ever be attached locally'),
        'icon'  => 'fas fa-user-lock',
        'accent' => '#0d6efd',
        'checked' => !empty($tag['local_only']),
    ],
];

echo $this->Form->create('Tag', [
    'id' => 'tagForm',
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
            <?= __('Tags') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-tag"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Tag') : __('Add Tag') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Tags label events, attributes and objects. Taxonomy tags follow the namespace:predicate="value" convention.') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-tag misp-simple text-tag"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-tag fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Tag Name') ?>
                <span class="badge bg-tag"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'TagName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. tlp:red or malware:apt'),
                'autocomplete' => 'off',
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Names are unique across the instance.') ?>
            </div>
        </div>

        <!-- ── COLOUR ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-tag fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Colour') ?>
            </div>
            <div class="d-flex align-items-center gap-3 flex-wrap">

                <?= $this->Form->input('colour', [
                    'label' => false,
                    'div' => false,
                    'type' => 'color',
                    'id' => 'TagColour',
                    'value' => $currentColour,
                    'class' => 'form-control form-control-color',
                    'style' => 'width:3rem; height:2.5rem; padding:.2rem;'
                        . ' border-color:#d8dde3; cursor:pointer;',
                ]) ?>

                <!-- Nameless, so it never reaches the POST: a mirror of the swatch -->
                <input type="text"
                       id="TagColourHex"
                       class="form-control font-monospace text-uppercase"
                       style="width:7.5rem; border-color:#d8dde3;"
                       maxlength="7"
                       autocomplete="off"
                       value="<?= h($currentColour) ?>">

                <button type="button"
                        class="btn btn-outline-secondary btn-sm"
                        id="TagColourShuffle"
                        title="<?= __('Suggest another colour') ?>">
                    <i class="fas fa-shuffle"></i>
                </button>

                <div class="d-flex align-items-center gap-2 ms-auto">
                    <span class="text-muted text-uppercase fw-bold"
                          style="font-size:.6rem; letter-spacing:.1em;">
                        <?= __('Preview') ?>
                    </span>
                    <span class="badge d-inline-flex align-items-center"
                          id="TagPreview"></span>
                </div>

            </div>
        </div>

        <!-- ── RESTRICTIONS ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-tag fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Restrictions') ?>
            </div>
            <div class="row g-3">

                <div class="<?= $isSiteAdmin ? 'col-md-6' : 'col-12' ?>">
                    <label class="form-label text-muted mb-1" for="TagOrgId"
                           style="font-size:.75rem;">
                        <i class="fas fa-building me-1" style="font-size:.7rem;"></i>
                        <?= __('Taggable by organisation') ?>
                    </label>
                    <?= $this->Form->select('org_id', $orgs ?? [], [
                        'id' => 'TagOrgId',
                        'class' => 'form-select tom-select',
                        'value' => $orgValue,
                        /* 'Unrestricted' is already option 0 — Form->select
                         * would otherwise prepend a blank one on top of it. */
                        'empty' => false,
                    ]) ?>
                </div>

                <?php if ($isSiteAdmin): ?>
                    <div class="col-md-6">
                        <label class="form-label text-muted mb-1" for="TagUserId"
                               style="font-size:.75rem;">
                            <i class="fas fa-user me-1" style="font-size:.7rem;"></i>
                            <?= __('Taggable by user') ?>
                        </label>
                        <?= $this->Form->select('user_id', $users ?? [], [
                            'id' => 'TagUserId',
                            'class' => 'form-select tom-select',
                            'value' => $userValue,
                            'empty' => false,
                        ]) ?>
                    </div>
                <?php endif; ?>

            </div>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-tag fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Options') ?>
            </div>
            <div class="row g-2">
                <?php foreach ($options as $field => $option): ?>
                    <div class="col-md-4">
                        <label class="d-flex align-items-center gap-3 rounded-2 p-3
                                      h-100 w-100 user-select-none mb-0"
                               data-option-card
                               data-accent="<?= h($option['accent']) ?>"
                               style="cursor:pointer; transition:border-color .15s;
                                      border:1px solid <?= $option['checked']
                                          ? h($option['accent']) : '#dee2e6' ?>;">
                            <?= $this->Form->checkbox($field, [
                                'id' => 'Tag' . Inflector::camelize($field),
                                'class' => 'form-check-input flex-shrink-0',
                                'style' => 'margin-top:0;',
                                'checked' => $option['checked'],
                            ]) ?>
                            <div class="flex-fill">
                                <div class="fw-bold text-uppercase"
                                     style="font-size:.72rem; letter-spacing:.06em;
                                            line-height:1.2;">
                                    <?= h($option['label']) ?>
                                </div>
                                <div class="text-muted"
                                     style="font-size:.76rem; margin-top:.2rem;
                                            line-height:1.3;">
                                    <?= h($option['hint']) ?>
                                </div>
                            </div>
                            <i class="<?= h($option['icon']) ?>" data-option-icon
                               style="font-size:.95rem; transition:color .15s;
                                      color:<?= $option['checked']
                                          ? h($option['accent']) : '#adb5bd' ?>;"></i>
                        </label>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($tag['id'])): ?>
                <?= __('Tag') ?>:
                <strong class="text-body">#<?= h($tag['id']) ?></strong>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Tag')),
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
    var PALETTE = <?= json_encode($paletteSuggestions,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var NAME_REQUIRED = <?= json_encode(__('Please provide a name for the tag.')) ?>;
    var NAME_EMPTY = <?= json_encode(__('your:tag')) ?>;
    var HEX_RE = /^#[0-9a-f]{6}$/i;

    var nameEl = document.getElementById('TagName');
    var colourEl = document.getElementById('TagColour');
    var hexEl = document.getElementById('TagColourHex');
    var shuffleEl = document.getElementById('TagColourShuffle');
    var previewEl = document.getElementById('TagPreview');
    var localEl = document.getElementById('TagLocalOnly');
    var form = document.getElementById('tagForm');

    /* Preview drawn with the shared helper, so it matches the badge the
     * index and the pickers render for a saved tag. */
    function refreshPreview() {
        if (!previewEl) { return; }
        var name = (nameEl && nameEl.value.trim()) || NAME_EMPTY;
        previewEl.style.cssText = tagBadgeStyle(colourEl ? colourEl.value : null);
        previewEl.textContent = '';
        if (localEl && localEl.checked) {
            var icon = document.createElement('i');
            icon.className = 'fas fa-user me-1';
            previewEl.appendChild(icon);
        }
        previewEl.appendChild(document.createTextNode(name));
    }

    function setColour(value) {
        if (!HEX_RE.test(value)) { return; }
        if (colourEl) { colourEl.value = value; }
        if (hexEl) { hexEl.value = value.toUpperCase(); }
        refreshPreview();
    }

    if (colourEl) {
        colourEl.addEventListener('input', function () {
            if (hexEl) { hexEl.value = colourEl.value.toUpperCase(); }
            refreshPreview();
        });
    }
    if (hexEl) {
        hexEl.addEventListener('input', function () {
            var value = hexEl.value.trim();
            if (value.charAt(0) !== '#') { value = '#' + value; }
            if (HEX_RE.test(value) && colourEl) {
                colourEl.value = value;
                refreshPreview();
            }
        });
        /* Snap the field back to the swatch when it is left half-typed */
        hexEl.addEventListener('blur', function () {
            if (colourEl) { hexEl.value = colourEl.value.toUpperCase(); }
        });
    }
    if (shuffleEl) {
        shuffleEl.addEventListener('click', function () {
            var current = colourEl ? colourEl.value.toUpperCase() : '';
            var pool = PALETTE.filter(function (c) { return c.toUpperCase() !== current; });
            setColour(pool[Math.floor(Math.random() * pool.length)]);
        });
    }
    if (nameEl) { nameEl.addEventListener('input', refreshPreview); }

    /* Option cards take their accent from the card itself */
    document.querySelectorAll('[data-option-card]').forEach(function (card) {
        var box = card.querySelector('input[type="checkbox"]');
        var icon = card.querySelector('[data-option-icon]');
        var accent = card.dataset.accent || '#0d6efd';
        if (!box) { return; }
        box.addEventListener('change', function () {
            card.style.borderColor = box.checked ? accent : '#dee2e6';
            if (icon) { icon.style.color = box.checked ? accent : '#adb5bd'; }
            if (box === localEl) { refreshPreview(); }
        });
    });

    if (form && nameEl) {
        var errorId = 'tagNameError';

        var showError = function () {
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
        };

        form.addEventListener('submit', function (e) {
            if (!nameEl.value.trim()) {
                e.preventDefault();
                e.stopPropagation();
                showError();
                nameEl.focus();
            }
        });

        nameEl.addEventListener('input', function () {
            if (nameEl.value.trim()) {
                nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
                var msg = document.getElementById(errorId);
                if (msg) { msg.remove(); }
            }
        });
    }

    refreshPreview();
})();
</script>
