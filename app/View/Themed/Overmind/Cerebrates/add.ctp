<?php
$isEdit = $this->request->params['action'] === 'edit';

$cerebrate = $this->request->data['Cerebrate'] ?? [];

$options = [
    [
        'field' => 'pull_orgs', 'id' => 'CerebratePullOrgs',
        'label' => __('Pull organisations'),
        'hint' => __('Fetch the organisations this Cerebrate knows'),
        'icon' => 'fas fa-building', 'accent' => '#1892B1',
    ],
    [
        'field' => 'pull_sharing_groups', 'id' => 'CerebratePullSharingGroups',
        'label' => __('Pull sharing groups'),
        'hint' => __('Fetch the sharing groups it publishes'),
        'icon' => 'misp-icon misp-icon-sharing-group misp-simple',
        'accent' => '#0d6efd',
    ],
    [
        'field' => 'skip_proxy', 'id' => 'CerebrateSkipProxy',
        'label' => __('Skip proxy'),
        'hint' => __('Reach it directly, ignoring the configured proxy'),
        'icon' => 'fas fa-diagram-project', 'accent' => '#6c757d',
    ],
];

echo $this->Form->create('Cerebrate', [
    'id' => 'cerebrateForm',
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
            <?= __('Cerebrates') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Cerebrate') : __('Add Cerebrate') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('A Cerebrate node this instance queries for organisation and sharing-group metadata.') ?>
        </p>
    </div>
    <i class="fas fa-network-wired text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Name') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'CerebrateName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. Community Cerebrate'),
                'autocomplete' => 'off',
            ]) ?>
        </div>

        <!-- ── CONNECTION ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Connection') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>

            <label class="form-label text-muted mb-1" for="CerebrateUrl"
                   style="font-size:.75rem;">
                <?= __('Base URL') ?>
            </label>
            <div class="input-group">
                <span class="input-group-text bg-transparent"
                      style="border-color:#d8dde3;">
                    <i class="fas fa-link text-muted" style="font-size:.8rem;"></i>
                </span>
                <?= $this->Form->text('url', [
                    'id' => 'CerebrateUrl',
                    'class' => 'form-control font-monospace',
                    'style' => 'border-color:#d8dde3;',
                    'placeholder' => 'https://cerebrate.example.org',
                    'autocomplete' => 'off',
                ]) ?>
            </div>

            <label class="form-label text-muted mb-1 mt-3" for="CerebrateAuthkey"
                   style="font-size:.75rem;">
                <?= __('Authentication key') ?>
            </label>
            <div class="input-group">
                <span class="input-group-text bg-transparent"
                      style="border-color:#d8dde3;">
                    <i class="fas fa-key text-muted" style="font-size:.8rem;"></i>
                </span>
                <?= $this->Form->text('authkey', [
                    'id' => 'CerebrateAuthkey',
                    'type' => 'password',
                    'class' => 'form-control font-monospace',
                    'style' => 'border-color:#d8dde3;',
                    'placeholder' => __('The API key of a Cerebrate user'),
                    'autocomplete' => 'new-password',
                ]) ?>
                <button type="button" class="btn btn-outline-secondary"
                        onclick="toggleSecret('CerebrateAuthkey', this)"
                        title="<?= __('Show or hide the key') ?>">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Used for every request this instance makes to the node.') ?>
            </div>
        </div>

        <!-- ── OWNER ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Owner Organisation') ?>
            </div>
            <?= $this->Form->select('org_id', $dropdownData['org_id'] ?? [], [
                'id' => 'CerebrateOrgId',
                'class' => 'form-select tom-select',
                'empty' => false,
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('The organisation this node is attributed to locally.') ?>
            </div>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Description') ?>
            </div>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'rows' => 2,
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('What this node is used for…'),
            ]) ?>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Options') ?>
            </div>
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

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Cerebrate') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Organisations and sharing groups are previewed before anything is pulled.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Cerebrate')),
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
    var L = {
        nameRequired: <?= json_encode(__('Please provide a name for the node.')) ?>,
        urlRequired: <?= json_encode(__('Please provide the base URL of the node.')) ?>,
        urlScheme: <?= json_encode(__('The URL has to start with http:// or https://')) ?>
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

    var nameEl = el('CerebrateName');
    var urlEl = el('CerebrateUrl');
    var form = el('cerebrateForm');
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
        if (existing) {
            existing.lastChild.textContent = message;
            return;
        }
        var msg = document.createElement('div');
        msg.id = errorId;
        msg.className = 'text-danger d-flex align-items-center gap-1';
        msg.style.fontSize = '.75rem';
        msg.style.marginTop = '.35rem';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        msg.appendChild(icon);
        msg.appendChild(document.createTextNode(message));
        var anchor = target.closest('.input-group') || target;
        anchor.parentNode.insertBefore(msg, anchor.nextSibling);
    }

    form.addEventListener('submit', function (e) {
        var problems = [];
        if (nameEl && !nameEl.value.trim()) {
            fieldError(nameEl, L.nameRequired, true);
            problems.push(nameEl);
        }
        if (urlEl) {
            var url = urlEl.value.trim();
            if (!url) {
                fieldError(urlEl, L.urlRequired, false);
                problems.push(urlEl);
            } else if (!/^https?:\/\//i.test(url)) {
                fieldError(urlEl, L.urlScheme, false);
                problems.push(urlEl);
            }
        }
        if (problems.length) {
            e.preventDefault();
            e.stopPropagation();
            problems[0].focus();
        }
    });

    [[nameEl, true], [urlEl, false]].forEach(function (pair) {
        if (!pair[0]) { return; }
        pair[0].addEventListener('input', function () {
            if (pair[0].value.trim()) { fieldError(pair[0], null, pair[1]); }
        });
    });
})();
</script>
