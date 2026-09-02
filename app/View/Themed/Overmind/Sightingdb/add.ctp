<?php
$isEdit = $this->request->params['action'] === 'edit';

$sightingdb = $this->request->data['Sightingdb'] ?? [];

$options = [
    [
        'field' => 'enabled', 'id' => 'SightingdbEnabled',
        'label' => __('Enabled'),
        'hint' => __('Query this database on attribute lookups'),
        'icon' => 'fas fa-power-off', 'accent' => '#198754',
    ],
    [
        'field' => 'skip_proxy', 'id' => 'SightingdbSkipProxy',
        'label' => __('Skip proxy'),
        'hint' => __('Reach it directly, ignoring the configured proxy'),
        'icon' => 'fas fa-diagram-project', 'accent' => '#6c757d',
    ],
    [
        'field' => 'ssl_skip_verification', 'id' => 'SightingdbSslSkipVerification',
        'label' => __('Skip SSL verification'),
        'hint' => __('Accept a certificate that does not validate'),
        'icon' => 'fas fa-shield-halved', 'accent' => '#dc3545',
    ],
];

echo $this->Form->create('Sightingdb', [
    'id' => 'sightingdbForm',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'sighting',
    'eyebrow' => __('Sighting Databases'),
    'title' => $isEdit ? __('Edit SightingDB') : __('Add SightingDB'),
    'description' => __('An external SightingDB queried for how often a value has been seen elsewhere.'),
    'icon' => 'misp-icon misp-icon-sighting misp-simple',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-sighting fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Name') ?>
                <span class="badge bg-sighting"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'SightingdbName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. Community SightingDB'),
                'autocomplete' => 'off',
            ]) ?>
        </div>

        <!-- ── ENDPOINT ────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'sighting',
                    'label' => __('Endpoint'),
                    'class' => '',
                ]) ?>
                <code class="text-muted" id="SightingdbEndpointPreview"
                      style="font-size:.72rem;"></code>
            </div>
            <div class="row g-3">
                <div class="col-md-7">
                    <label class="form-label text-muted mb-1" for="SightingdbHost"
                           style="font-size:.75rem;">
                        <i class="fas fa-server me-1" style="font-size:.7rem;"></i>
                        <?= __('Host') ?>
                    </label>
                    <?= $this->Form->text('host', [
                        'id' => 'SightingdbHost',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => 'http://localhost',
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-5">
                    <label class="form-label text-muted mb-1" for="SightingdbPort"
                           style="font-size:.75rem;">
                        <?= __('Port') ?>
                    </label>
                    <?= $this->Form->text('port', [
                        'id' => 'SightingdbPort',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => '9999',
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-7">
                    <label class="form-label text-muted mb-1" for="SightingdbNamespace"
                           style="font-size:.75rem;">
                        <?= __('Namespace') ?>
                    </label>
                    <?= $this->Form->text('namespace', [
                        'id' => 'SightingdbNamespace',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => __('Left empty, the root namespace is used'),
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-5">
                    <label class="form-label text-muted mb-1" for="SightingdbOwner"
                           style="font-size:.75rem;">
                        <?= __('Owner') ?>
                    </label>
                    <?= $this->Form->text('owner', [
                        'id' => 'SightingdbOwner',
                        'class' => 'form-control',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => __('Who runs it'),
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── VISIBILITY ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'sighting',
                'label' => __('Organisation Restrictions'),
            ]) ?>
            <?= $this->Form->select('org_id', $orgs ?? [], [
                'multiple' => true,
                'class' => 'form-select tom-select',
                'data-placeholder' => __('Every organisation'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Left empty, the results are visible to every organisation.'),
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'sighting',
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'rows' => 2,
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('What this database covers…'),
            ]) ?>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'sighting',
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
                                      border:1px solid #dee2e6;">
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
                                      color:#adb5bd;"></i>
                        </label>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'sighting',
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('SightingDB'), 'id' => $id]] : [],
        'hint' => __('Nothing is queried until the database is enabled.'),
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add SightingDB')],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var L = {
        nameRequired: <?= json_encode(__('Please provide a name for the database.')) ?>,
        hostRequired: <?= json_encode(__('Please provide the host to query.')) ?>
    };

    function el(id) { return document.getElementById(id); }

    /* Option cards take their accent from the card itself */
    function paintCard(card) {
        var box = card.querySelector('input[type="checkbox"]');
        var icon = card.querySelector('[data-option-icon]');
        var accent = card.dataset.accent || '#0d6efd';
        if (!box) { return; }
        card.style.borderColor = box.checked ? accent : '#dee2e6';
        if (icon) { icon.style.color = box.checked ? accent : '#adb5bd'; }
    }
    document.querySelectorAll('[data-option-card]').forEach(function (card) {
        var box = card.querySelector('input[type="checkbox"]');
        if (box) { box.addEventListener('change', function () { paintCard(card); }); }
        paintCard(card);
    });

    /* Host, port and namespace are queried as one URL — show it being built */
    var hostEl = el('SightingdbHost');
    var portEl = el('SightingdbPort');
    var namespaceEl = el('SightingdbNamespace');
    var previewEl = el('SightingdbEndpointPreview');

    function refreshPreview() {
        if (!previewEl) { return; }
        var host = (hostEl ? hostEl.value.trim() : '') || 'http://localhost';
        var port = (portEl ? portEl.value.trim() : '') || '9999';
        var namespace = namespaceEl ? namespaceEl.value.trim() : '';
        previewEl.textContent = host.replace(/\/+$/, '') + ':' + port
            + '/' + (namespace ? namespace.replace(/^\/+/, '') + '/' : '');
    }
    [hostEl, portEl, namespaceEl].forEach(function (field) {
        if (field) { field.addEventListener('input', refreshPreview); }
    });
    refreshPreview();

    var nameEl = el('SightingdbName');
    var form = el('sightingdbForm');
    if (!form) { return; }

    function fieldError(target, message, underlined) {
        var errorId = target.id + 'Error';
        var existing = el(errorId);
        var property = underlined ? 'border-bottom-color' : 'border-color';
        if (!message) {
            target.style.setProperty(property, '#d8dde3', 'important');
            if (existing) { existing.remove(); }
            return;
        }
        target.style.setProperty(property, '#dc3545', 'important');
        if (existing) { return; }
        var msg = document.createElement('div');
        msg.id = errorId;
        msg.className = 'text-danger d-flex align-items-center gap-1';
        msg.style.fontSize = '.75rem';
        msg.style.marginTop = '.35rem';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        msg.appendChild(icon);
        msg.appendChild(document.createTextNode(message));
        target.parentNode.insertBefore(msg, target.nextSibling);
    }

    form.addEventListener('submit', function (e) {
        var problems = [];
        if (nameEl && !nameEl.value.trim()) {
            fieldError(nameEl, L.nameRequired, true);
            problems.push(nameEl);
        }
        if (hostEl && !hostEl.value.trim()) {
            fieldError(hostEl, L.hostRequired, false);
            problems.push(hostEl);
        }
        if (problems.length) {
            e.preventDefault();
            e.stopPropagation();
            problems[0].focus();
        }
    });

    [[nameEl, true], [hostEl, false]].forEach(function (pair) {
        if (!pair[0]) { return; }
        pair[0].addEventListener('input', function () {
            if (pair[0].value.trim()) { fieldError(pair[0], null, pair[1]); }
        });
    });
})();
</script>
