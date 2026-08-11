<?php
$isEdit = $this->request->params['action'] === 'edit';

$variable = $this->request->data['EventReportTemplateVariable'] ?? [];
$variableId = $variable['id'] ?? ($this->request->params['pass'][0] ?? null);

echo $this->Form->create('EventReportTemplateVariable', [
    'id' => 'templateVariableForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(77,161,103,.06);
            border-bottom:2px solid var(--bs-report);">
    <div>
        <div class="text-report text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Event Report Templates') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-report"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Template Variable') : __('Add Template Variable') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('The value replaces the variable\'s placeholder wherever it appears in an event report template.') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-report misp-simple text-report"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-report fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Variable Name') ?>
                <span class="badge bg-report"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'TemplateVariableName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. incident_summary'),
                'autocomplete' => 'off',
            ]) ?>
            <div class="d-flex align-items-center gap-2 mt-2 text-muted"
                 style="font-size:.75rem;">
                <?= __('Placeholder') ?>:
                <!-- Same chip as the index, kept in sync by the script below -->
                <span class="d-inline-flex align-items-center bg-light rounded
                             border border-secondary-subtle p-1"
                      id="templateVariablePreview">
                    <span class="px-2 bg-dark text-white rounded-start small fw-bold">{{</span>
                    <code class="px-2 bg-transparent text-dark fw-semibold small"
                          id="templateVariablePreviewName"></code>
                    <span class="px-2 bg-dark text-white rounded-end small fw-bold">}}</span>
                </span>
            </div>
        </div>

        <!-- ── VALUE ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-report fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Value') ?>
            </div>
            <?= $this->Form->textarea('value', [
                'id' => 'TemplateVariableValue',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.875rem; min-height:200px;'
                    . ' color:inherit; font-family:monospace;',
                'rows' => 10,
                'placeholder' => __('Write the content the placeholder expands to…'),
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Inserted as-is into the report, so Markdown and MISP element references work here too.') ?>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($variableId)): ?>
                <?= __('Variable') ?>:
                <strong class="text-body">#<?= h($variableId) ?></strong>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Variable')),
                [
                    'class' => 'btn btn-report btn-sm text-white',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var NAME_REQUIRED = <?= json_encode(__('Please provide a name for the variable.')) ?>;
    var NAME_EMPTY = <?= json_encode(__('variable_name')) ?>;

    var nameEl = document.getElementById('TemplateVariableName');
    var previewEl = document.getElementById('templateVariablePreviewName');
    var form = document.getElementById('templateVariableForm');

    if (nameEl && previewEl) {
        var refreshPreview = function () {
            var value = nameEl.value.trim();
            previewEl.textContent = value || NAME_EMPTY;
            previewEl.style.opacity = value ? '1' : '.5';
        };
        nameEl.addEventListener('input', refreshPreview);
        refreshPreview();
    }

    if (form && nameEl) {
        var errorId = 'templateVariableNameError';

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

        var clearError = function () {
            nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
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
            if (nameEl.value.trim()) { clearError(); }
        });
    }
})();
</script>
