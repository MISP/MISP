<?php
$isEdit = $this->request->params['action'] === 'admin_edit';

echo $this->Form->create('Allowedlist', [
    'id' => 'allowedlistForm',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Signature Allowedlist'),
    'title' => $isEdit ? __('Edit Allowedlist Entry') : __('Add Allowedlist Entry'),
    'description' => __('An attribute whose value matches this expression is left out of the IDS-flagged exports, such as the NIDS ones.'),
    'icon' => 'fas fa-shield-halved',
    'isEdit' => $isEdit,
]) ?>

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

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('Entry'), 'id' => $id]] : [],
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Entry')],
    ]) ?>

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
