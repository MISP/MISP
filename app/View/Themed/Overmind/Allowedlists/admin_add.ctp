<?php
$isEdit = $this->request->params['action'] === 'admin_edit';

echo $this->Form->create('Allowedlist', [
    'id' => 'allowedlistForm',
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
            <?= __('Signature Allowedlist') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Allowedlist Entry') : __('Add Allowedlist Entry') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('An attribute whose value matches this expression is left out of the IDS-flagged exports, such as the NIDS ones.') ?>
        </p>
    </div>
    <i class="fas fa-shield-halved text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── EXPRESSION ──────────────────────────────────────── -->
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
            <?= $this->Form->text('name', [
                'id' => 'AllowedlistName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1 font-monospace',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => '/8.8.8.8/',
                'autocomplete' => 'off',
            ]) ?>
            <!-- Live read of the delimiters; the model runs the real check -->
            <div class="d-flex align-items-center gap-1 mt-1"
                 id="AllowedlistNameStatus" style="font-size:.75rem;"></div>
            <div class="d-flex align-items-start gap-2 rounded-2 p-2 mt-2 small"
                 style="background:rgba(24,146,177,.05);
                        border:1px solid rgba(24,146,177,.25);">
                <i class="fas fa-circle-info text-primary mt-1"
                   style="font-size:.7rem;"></i>
                <div class="text-muted">
                    <?= __('The entry is a PHP regular expression and has to carry its delimiters — most non-alphanumeric, non-whitespace character will do.') ?>
                    <br>
                    <?= __('Anchor it when you mean an exact value: %s matches 8.8.8.8 alone, while %s also matches 18.8.8.81.', '<code>/^8\.8\.8\.8$/</code>', '<code>/8.8.8.8/</code>') ?>
                </div>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Entry') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Entry')),
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
    var NAME_REQUIRED = <?= json_encode(__('Please provide an expression.')) ?>;
    var LOOKS_VALID = <?= json_encode(__('Delimited pattern')) ?>;
    var LOOKS_OFF = <?= json_encode(__('Enclose the pattern in a delimiter, e.g. /8.8.8.8/')) ?>;
    /* delimiter + body + same delimiter + optional modifiers */
    var DELIMITED = /^([^a-zA-Z0-9\s\\])(.+)\1[imsxuADSUXJn]*$/;

    var nameEl = document.getElementById('AllowedlistName');
    var statusEl = document.getElementById('AllowedlistNameStatus');
    var form = document.getElementById('allowedlistForm');
    if (!nameEl || !form) { return; }

    function setStatus(kind, message) {
        statusEl.innerHTML = '';
        if (!kind) { return; }
        var icon = document.createElement('i');
        var text = document.createElement('span');
        if (kind === 'ok') {
            statusEl.className = 'd-flex align-items-center gap-1 mt-1 text-success';
            icon.className = 'fas fa-circle-check';
        } else if (kind === 'warn') {
            statusEl.className = 'd-flex align-items-center gap-1 mt-1 text-warning-emphasis';
            icon.className = 'fas fa-triangle-exclamation';
        } else {
            statusEl.className = 'd-flex align-items-center gap-1 mt-1 text-danger';
            icon.className = 'fas fa-circle-exclamation';
        }
        icon.style.fontSize = '.7rem';
        text.textContent = message;
        statusEl.appendChild(icon);
        statusEl.appendChild(text);
    }

    function refresh() {
        var value = nameEl.value.trim();
        nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
        if (!value) { setStatus(null); return; }
        setStatus(DELIMITED.test(value) ? 'ok' : 'warn',
                  DELIMITED.test(value) ? LOOKS_VALID : LOOKS_OFF);
    }

    nameEl.addEventListener('input', refresh);
    refresh();

    form.addEventListener('submit', function (e) {
        if (nameEl.value.trim()) { return; }
        e.preventDefault();
        e.stopPropagation();
        nameEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
        setStatus('error', NAME_REQUIRED);
        nameEl.focus();
    });
})();
</script>
