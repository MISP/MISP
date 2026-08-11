<?php
$isEdit = $this->request->params['action'] === 'edit';

$exclusion = $this->request->data['CorrelationExclusion'] ?? [];
$currentValue = $exclusion['value'] ?? '';

echo $this->Form->create('CorrelationExclusion', [
    'id' => 'correlationExclusionForm',
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
            <?= __('Correlation Exclusions') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Exclusion') : __('Add Exclusion') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('An excluded value never correlates — useful for values so common that their correlations carry no meaning.') ?>
        </p>
    </div>
    <i class="fas fa-link-slash text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── VALUE ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 text-primary fw-bold
                            text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Value') ?>
                    <?php if (!$isEdit): ?>
                        <span class="badge bg-primary"
                              style="font-size:.55rem; opacity:.8; font-weight:700;">
                            <?= __('REQUIRED') ?>
                        </span>
                    <?php endif; ?>
                </div>
                <?php if (!$isEdit): ?>
                    <span class="badge bg-light text-muted border"
                          id="ExclusionMatchMode" style="font-size:.65rem;"></span>
                <?php endif; ?>
            </div>

            <?php if ($isEdit): ?>
                <!-- edit() only saves the comment; the value is immutable -->
                <div class="border rounded px-3 py-2 bg-light d-flex
                            align-items-center gap-2">
                    <i class="fas fa-lock text-muted" style="font-size:.7rem;"></i>
                    <code class="text-body"><?= h($currentValue) ?></code>
                </div>
                <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                     style="font-size:.75rem;">
                    <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                    <?= __('The value cannot be changed — delete this entry and add the new value instead.') ?>
                </div>
            <?php else: ?>
                <?= $this->Form->text('value', [
                    'id' => 'ExclusionValue',
                    'class' => 'w-100 border-0 bg-transparent fs-5 py-1 font-monospace',
                    'style' => 'border-bottom:1px solid #d8dde3 !important;'
                        . ' outline:none;',
                    'placeholder' => '8.8.8.8',
                    'autocomplete' => 'off',
                ]) ?>
                <div class="d-flex align-items-start gap-2 rounded-2 p-2 mt-2 small"
                     style="background:rgba(24,146,177,.05);
                            border:1px solid rgba(24,146,177,.25);">
                    <i class="fas fa-circle-info text-primary mt-1"
                       style="font-size:.7rem;"></i>
                    <div class="text-muted">
                        <?= __('A leading or trailing %s makes the match partial:', '<code>%</code>') ?>
                        <code>8.8.8.%</code> <?= __('starts with') ?> ·
                        <code>%.local</code> <?= __('ends with') ?> ·
                        <code>%internal%</code> <?= __('contains') ?> ·
                        <?= __('without one, the value has to match exactly.') ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Comment') ?>
            </div>
            <?= $this->Form->textarea('comment', [
                'id' => 'ExclusionComment',
                'class' => 'form-control',
                'rows' => 3,
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('Why this value is not worth correlating on…'),
            ]) ?>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Exclusion') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Existing correlations are dropped by "Clean up correlations".') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Exclusion')),
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
    var VALUE_REQUIRED = <?= json_encode(__('Please provide a value to exclude.')) ?>;
    var MODES = {
        exact: <?= json_encode(__('Exact match')) ?>,
        starts: <?= json_encode(__('Starts with')) ?>,
        ends: <?= json_encode(__('Ends with')) ?>,
        contains: <?= json_encode(__('Contains')) ?>
    };

    var valueEl = document.getElementById('ExclusionValue');
    var modeEl = document.getElementById('ExclusionMatchMode');
    var form = document.getElementById('correlationExclusionForm');
    if (!valueEl || !form) { return; }

    /* Mirrors Correlation::__preventExcludedCorrelations() */
    function refreshMode() {
        if (!modeEl) { return; }
        var value = valueEl.value.trim();
        if (!value) { modeEl.textContent = ''; return; }
        var head = value.charAt(0) === '%';
        var tail = value.charAt(value.length - 1) === '%' && value.length > 1;
        var mode = head && tail ? 'contains' : (head ? 'ends' : (tail ? 'starts' : 'exact'));
        modeEl.textContent = MODES[mode];
    }

    valueEl.addEventListener('input', function () {
        refreshMode();
        if (valueEl.value.trim()) {
            valueEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
            var msg = document.getElementById('ExclusionValueError');
            if (msg) { msg.remove(); }
        }
    });
    refreshMode();

    form.addEventListener('submit', function (e) {
        if (valueEl.value.trim()) { return; }
        e.preventDefault();
        e.stopPropagation();
        valueEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
        if (!document.getElementById('ExclusionValueError')) {
            var msg = document.createElement('div');
            msg.id = 'ExclusionValueError';
            msg.className = 'text-danger d-flex align-items-center gap-1';
            msg.style.fontSize = '.75rem';
            msg.style.marginTop = '.35rem';
            var icon = document.createElement('i');
            icon.className = 'fas fa-circle-exclamation';
            msg.appendChild(icon);
            msg.appendChild(document.createTextNode(VALUE_REQUIRED));
            valueEl.parentNode.insertBefore(msg, valueEl.nextSibling);
        }
        valueEl.focus();
    });
})();
</script>
