<?php
$isEdit = $this->request->params['action'] === 'admin_edit';

/* admin_edit() hands the per-type state over as $value (type key => bool) and
 * $all; the multiple select has to be pre-selected from it, or an edit would
 * silently drop the types the entry already covers. */
$selectedTypes = array_keys(array_filter($value ?? []));
$allTypes = !empty($all);

echo $this->Form->create('Regexp', [
    'id' => 'regexpForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Import Regular Expressions') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Regexp') : __('Add Regexp') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Every attribute value entered through the UI or an import is run through these expressions and rewritten with the replacement.') ?>
        </p>
    </div>
    <i class="fas fa-code text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── REGEXP ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Expression') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('regexp', [
                'id' => 'RegexpRegexp',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1 font-monospace',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'maxlength' => 255,
                'placeholder' => '/^127\.0\.0\.1$/',
                'autocomplete' => 'off',
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('A PHP pattern, delimiters included — e.g. /^10\.0\.0\.\d+$/i.') ?>
            </div>
        </div>

        <!-- ── REPLACEMENT ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Replacement') ?>
            </div>
            <?= $this->Form->text('replacement', [
                'id' => 'RegexpReplacement',
                'class' => 'form-control font-monospace',
                'style' => 'border-color:#d8dde3;',
                'maxlength' => 255,
                'placeholder' => __('Left empty, a matching value is blocked instead of rewritten'),
                'autocomplete' => 'off',
            ]) ?>
        </div>

        <!-- ── AFFECTED TYPES ──────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Affected Attribute Types') ?>
            </div>

            <label class="d-flex align-items-center gap-3 rounded-2 p-3 w-100
                          user-select-none mb-2"
                   id="RegexpAllCard"
                   style="cursor:pointer; transition:border-color .15s;
                          border:1px solid <?= $allTypes ? 'var(--primary)' : '#dee2e6' ?>;">
                <?= $this->Form->checkbox('all', [
                    'id' => 'RegexpAll',
                    'class' => 'form-check-input flex-shrink-0',
                    'style' => 'margin-top:0;',
                    'hiddenField' => true,
                    'checked' => $allTypes,
                ]) ?>
                <div class="flex-fill">
                    <div class="fw-bold text-uppercase"
                         style="font-size:.72rem; letter-spacing:.06em; line-height:1.2;">
                        <?= __('Apply to every type') ?>
                    </div>
                    <div class="text-muted"
                         style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                        <?= __('Overrides the selection below') ?>
                    </div>
                </div>
                <i class="fas fa-asterisk" id="RegexpAllIcon"
                   style="font-size:.95rem; transition:color .15s;
                          color:<?= $allTypes ? 'var(--primary)' : '#adb5bd' ?>;"></i>
            </label>

            <div id="RegexpTypesContainer"
                 style="transition:opacity .15s;
                        <?= $allTypes ? 'opacity:.4; pointer-events:none;' : '' ?>">
                <?= $this->Form->select('selected_types', $types, [
                    'id' => 'RegexpSelectedTypes',
                    'multiple' => true,
                    'class' => 'form-select tom-select',
                    'value' => $selectedTypes,
                    'data-placeholder' => __('Pick the types this expression applies to…'),
                ]) ?>
                <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                     style="font-size:.75rem;">
                    <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                    <?= __('One entry is created per selected type.') ?>
                </div>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit): ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Saving replaces the entries of this expression.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Regexp')),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var REGEXP_REQUIRED = <?= json_encode(__('Please provide an expression.')) ?>;
    var TYPES_REQUIRED = <?= json_encode(__('Pick at least one type, or apply the expression to every type.')) ?>;

    var allBox = document.getElementById('RegexpAll');
    var allCard = document.getElementById('RegexpAllCard');
    var allIcon = document.getElementById('RegexpAllIcon');
    var typesWrap = document.getElementById('RegexpTypesContainer');
    var typesEl = document.getElementById('RegexpSelectedTypes');
    var regexpEl = document.getElementById('RegexpRegexp');
    var form = document.getElementById('regexpForm');

    /* 'all' wins server-side, so the type list is dimmed out rather than left
     * looking like it still matters. It stays submitted, just ignored. */
    function refreshAll() {
        var on = allBox.checked;
        allCard.style.borderColor = on ? 'var(--primary)' : '#dee2e6';
        if (allIcon) { allIcon.style.color = on ? 'var(--primary)' : '#adb5bd'; }
        typesWrap.style.opacity = on ? '.4' : '';
        typesWrap.style.pointerEvents = on ? 'none' : '';
        if (on) { clearError('RegexpTypesError'); }
    }
    if (allBox && allCard && typesWrap) {
        allBox.addEventListener('change', refreshAll);
    }

    function clearError(id) {
        var msg = document.getElementById(id);
        if (msg) { msg.remove(); }
    }

    function showError(id, anchor, message, underlined) {
        if (underlined) {
            anchor.style.setProperty('border-bottom-color', '#dc3545', 'important');
        }
        if (document.getElementById(id)) { return; }
        var msg = document.createElement('div');
        msg.id = id;
        msg.className = 'text-danger d-flex align-items-center gap-1';
        msg.style.fontSize = '.75rem';
        msg.style.marginTop = '.35rem';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        msg.appendChild(icon);
        msg.appendChild(document.createTextNode(message));
        anchor.parentNode.insertBefore(msg, anchor.nextSibling);
    }

    if (form) {
        form.addEventListener('submit', function (e) {
            var noRegexp = !regexpEl.value.trim();
            var noTypes = !allBox.checked
                && (!typesEl || typesEl.selectedOptions.length === 0);

            if (noRegexp) {
                showError('RegexpRegexpError', regexpEl, REGEXP_REQUIRED, true);
            }
            if (noTypes) {
                showError('RegexpTypesError', typesWrap, TYPES_REQUIRED, false);
            }
            if (noRegexp || noTypes) {
                e.preventDefault();
                e.stopPropagation();
                (noRegexp ? regexpEl : typesEl).focus();
            }
        });

        regexpEl.addEventListener('input', function () {
            if (!regexpEl.value.trim()) { return; }
            regexpEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
            clearError('RegexpRegexpError');
        });
        if (typesEl) {
            typesEl.addEventListener('change', function () {
                if (typesEl.selectedOptions.length) { clearError('RegexpTypesError'); }
            });
        }
    }
})();
</script>
