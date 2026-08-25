<?php
$isEdit = $this->request->params['action'] === 'edit';

$server = $this->request->data['TaxiiServer'] ?? [];

$currentAuthType = $server['auth_type'] ?? 'basic';
$currentApiRoot = $server['api_root'] ?? '';
$currentCollection = $server['collection'] ?? '';

/* Pretty-print the restsearch filters for editing */
$filters = $server['filters'] ?? '';
if ($filters !== '') {
    $decodedFilters = json_decode($filters);
    if ($decodedFilters !== null) {
        $filters = json_encode($decodedFilters, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}

$authTypes = ['basic' => __('Basic'), 'bearer' => __('Bearer')];

$options = [
    [
        'field' => 'enabled', 'id' => 'TaxiiServerEnabled',
        'label' => __('Enabled'),
        'hint' => __('Available as a push target'),
        'icon' => 'fas fa-power-off', 'accent' => '#198754',
        'checked' => $isEdit ? !empty($server['enabled']) : true,
    ],
    [
        'field' => 'skip_proxy', 'id' => 'TaxiiServerSkipProxy',
        'label' => __('Skip proxy'),
        'hint' => __('Reach it directly, ignoring the configured proxy'),
        'icon' => 'fas fa-diagram-project', 'accent' => '#6c757d',
        'checked' => !empty($server['skip_proxy']),
    ],
];

echo $this->Form->create('TaxiiServer', [
    'id' => 'taxiiServerForm',
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
            <?= __('TAXII Servers') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit TAXII Server') : __('Add TAXII Server') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('A TAXII 2.1 collection this instance can push STIX to — the discovery URL leads to the API roots.') ?>
        </p>
    </div>
    <i class="fas fa-cloud text-primary" style="font-size:2rem; opacity:.45;"></i>
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
                'id' => 'TaxiiServerName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. Partner TAXII collection'),
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

            <label class="form-label text-muted mb-1" for="TaxiiServerDiscoveryUrl"
                   style="font-size:.75rem;">
                <?= __('Discovery URL') ?>
            </label>
            <div class="input-group">
                <span class="input-group-text bg-transparent"
                      style="border-color:#d8dde3;">
                    <i class="fas fa-link text-muted" style="font-size:.8rem;"></i>
                </span>
                <?php
                    echo $this->Form->text('discovery_url', [
                        'id' => 'TaxiiServerDiscoveryUrl',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => 'https://example.org/taxii2/',
                        'autocomplete' => 'off',
                    ]);
                ?>
            </div>

            <div class="row g-3 mt-1">
                <div class="col-md-4">
                    <label class="form-label text-muted mb-1" for="TaxiiServerAuthType"
                           style="font-size:.75rem;">
                        <?= __('Authentication') ?>
                    </label>
                    <?= $this->Form->select('auth_type', $authTypes, [
                        'id' => 'TaxiiServerAuthType',
                        'class' => 'form-select',
                        'value' => $currentAuthType,
                        'empty' => false,
                    ]) ?>
                </div>

                <div class="col-md-4 taxii-auth-basic">
                    <label class="form-label text-muted mb-1" for="TaxiiServerUsername"
                           style="font-size:.75rem;">
                        <?= __('Username') ?>
                    </label>
                    <?= $this->Form->text('username', [
                        'id' => 'TaxiiServerUsername',
                        'class' => 'form-control',
                        'style' => 'border-color:#d8dde3;',
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-4 taxii-auth-basic">
                    <label class="form-label text-muted mb-1" for="TaxiiServerPassword"
                           style="font-size:.75rem;">
                        <?= __('Password') ?>
                    </label>
                    <div class="input-group">
                        <?= $this->Form->text('password', [
                            'id' => 'TaxiiServerPassword',
                            'type' => 'password',
                            'class' => 'form-control',
                            'style' => 'border-color:#d8dde3;',
                            'autocomplete' => 'new-password',
                        ]) ?>
                        <button type="button" class="btn btn-outline-secondary"
                                onclick="toggleSecret('TaxiiServerPassword', this)"
                                title="<?= __('Show or hide') ?>">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>

                <div class="col-md-8 taxii-auth-bearer">
                    <label class="form-label text-muted mb-1" for="TaxiiServerApiKey"
                           style="font-size:.75rem;">
                        <span id="TaxiiServerApiKeyLabel"><?= __('Bearer token') ?></span>
                    </label>
                    <div class="input-group">
                        <span class="input-group-text bg-transparent"
                              style="border-color:#d8dde3;">
                            <i class="fas fa-key text-muted" style="font-size:.8rem;"></i>
                        </span>
                        <?= $this->Form->text('api_key', [
                            'id' => 'TaxiiServerApiKey',
                            'type' => 'password',
                            'class' => 'form-control font-monospace',
                            'style' => 'border-color:#d8dde3;',
                            'autocomplete' => 'new-password',
                        ]) ?>
                        <button type="button" class="btn btn-outline-secondary"
                                onclick="toggleSecret('TaxiiServerApiKey', this)"
                                title="<?= __('Show or hide') ?>">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
            </div>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 id="TaxiiServerAuthHint" style="font-size:.75rem;"></div>
        </div>

        <!-- ── TARGET COLLECTION ───────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="text-primary fw-bold text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Target Collection') ?>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <span id="taxiiProbeStatus" class="badge bg-secondary d-none"
                          style="font-size:.65rem;"></span>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="taxiiProbeBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-satellite-dish me-1"></i><?= __('Discover') ?>
                    </button>
                </div>
            </div>

            <div class="row g-3">
                <div class="col-md-7">
                    <label class="form-label text-muted mb-1" for="TaxiiServerApiRoot"
                           style="font-size:.75rem;">
                        <?= __('API root') ?>
                    </label>
                    <select id="TaxiiServerApiRoot"
                            name="data[TaxiiServer][api_root]"
                            class="form-select">
                        <?php if ($currentApiRoot !== ''): ?>
                            <option value="<?= h($currentApiRoot) ?>" selected>
                                <?= h($currentApiRoot) ?>
                            </option>
                        <?php endif; ?>
                    </select>
                </div>
                <div class="col-md-5">
                    <label class="form-label text-muted mb-1" for="TaxiiServerCollection"
                           style="font-size:.75rem;">
                        <?= __('Collection') ?>
                    </label>
                    <select id="TaxiiServerCollection"
                            name="data[TaxiiServer][collection]"
                            class="form-select">
                        <?php if ($currentCollection !== ''): ?>
                            <option value="<?= h($currentCollection) ?>" selected>
                                <?= h($currentCollection) ?>
                            </option>
                        <?php endif; ?>
                    </select>
                </div>
            </div>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Discover asks the server for its API roots, then for the collections you may write to.') ?>
            </div>
        </div>

        <!-- ── FILTERS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="text-primary fw-bold text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Filter Rules') ?>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <span id="taxiiFiltersStatus" class="badge bg-secondary"
                          style="font-size:.65rem;"></span>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="taxiiFiltersFormatBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Format') ?>
                    </button>
                </div>
            </div>
            <?= $this->Form->textarea('filters', [
                'id' => 'TaxiiServerFilters',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.85rem; min-height:120px;'
                    . ' color:inherit; font-family:monospace;'
                    . ' white-space:pre; overflow-x:auto;',
                'rows' => 5,
                'spellcheck' => 'false',
                'value' => $filters,
                'placeholder' => "{\n    \"tags\": [\"tlp:white\"],\n    \"published\": 1\n}",
            ]) ?>
            <div id="taxiiFiltersError" class="d-none text-danger
                        d-flex align-items-center gap-1 mt-1"
                 style="font-size:.75rem;"></div>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('A restsearch filter object — it decides which events are pushed.') ?>
            </div>
        </div>

        <!-- ── OWNER / DESCRIPTION ─────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Bookkeeping') ?>
            </div>
            <div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label text-muted mb-1" for="TaxiiServerOwner"
                           style="font-size:.75rem;">
                        <?= __('Owner') ?>
                    </label>
                    <?= $this->Form->text('owner', [
                        'id' => 'TaxiiServerOwner',
                        'class' => 'form-control',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => __('Who runs the server'),
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-12">
                    <label class="form-label text-muted mb-1" for="TaxiiServerDescription"
                           style="font-size:.75rem;">
                        <?= __('Description') ?>
                    </label>
                    <?= $this->Form->textarea('description', [
                        'id' => 'TaxiiServerDescription',
                        'class' => 'form-control',
                        'rows' => 2,
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => __('What is pushed there…'),
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Options') ?>
            </div>
            <div class="row g-2">
                <?php foreach ($options as $option): ?>
                    <div class="col-md-6">
                        <label class="d-flex align-items-center gap-3 rounded-2 p-3
                                      h-100 w-100 user-select-none mb-0"
                               data-option-card
                               data-accent="<?= h($option['accent']) ?>"
                               style="cursor:pointer; transition:border-color .15s;
                                      border:1px solid <?= $option['checked']
                                          ? h($option['accent']) : '#dee2e6' ?>;">
                            <?= $this->Form->checkbox($option['field'], [
                                'id' => $option['id'],
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
                                     style="font-size:.74rem; margin-top:.2rem;
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
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Server') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Basic credentials are stored as the encoded API key.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Server')),
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
    var BASE = <?= json_encode($baseurl, JSON_HEX_TAG | JSON_HEX_AMP
        | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var L = {
        basicHint: <?= json_encode(__('The username and password are stored as one encoded API key.')) ?>,
        bearerHint: <?= json_encode(__('The token is sent as an Authorization: Bearer header.')) ?>,
        bearerLabel: <?= json_encode(__('Bearer token')) ?>,
        basicLabel: <?= json_encode(__('API key (filled from the credentials)')) ?>,
        probing: <?= json_encode(__('Discovering…')) ?>,
        roots: <?= json_encode(__('%s API root(s)')) ?>,
        collections: <?= json_encode(__('%s collection(s)')) ?>,
        probeFailed: <?= json_encode(__('Discovery failed')) ?>,
        urlNeeded: <?= json_encode(__('Fill the discovery URL first.')) ?>,
        nameRequired: <?= json_encode(__('Please provide a name for the server.')) ?>,
        urlRequired: <?= json_encode(__('Please provide the discovery URL.')) ?>,
        urlScheme: <?= json_encode(__('The URL has to start with http:// or https://')) ?>,
        filtersEmpty: <?= json_encode(__('No filter')) ?>,
        filtersValid: <?= json_encode(__('Valid')) ?>,
        filtersInvalid: <?= json_encode(__('Invalid JSON')) ?>,
        objectExpected: <?= json_encode(__('The filters have to be a JSON object.')) ?>
    };

    function el(id) { return document.getElementById(id); }

    /* ── Option cards ── */
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
    });

    /* ── Auth type drives which credential fields apply ── */
    var authEl = el('TaxiiServerAuthType');
    var authHintEl = el('TaxiiServerAuthHint');
    var apiKeyLabel = el('TaxiiServerApiKeyLabel');

    function refreshAuth() {
        var isBasic = !authEl || authEl.value === 'basic';
        document.querySelectorAll('.taxii-auth-basic').forEach(function (node) {
            node.style.display = isBasic ? '' : 'none';
        });
        document.querySelectorAll('.taxii-auth-bearer').forEach(function (node) {
            node.classList.toggle('col-md-8', !isBasic);
            node.classList.toggle('col-md-4', isBasic);
        });
        if (apiKeyLabel) {
            apiKeyLabel.textContent = isBasic ? L.basicLabel : L.bearerLabel;
        }
        if (authHintEl) {
            authHintEl.innerHTML = '';
            var icon = document.createElement('i');
            icon.className = 'fas fa-circle-info';
            icon.style.fontSize = '.65rem';
            authHintEl.appendChild(icon);
            authHintEl.appendChild(document.createTextNode(
                isBasic ? L.basicHint : L.bearerHint));
        }
    }
    if (authEl) { authEl.addEventListener('change', refreshAuth); }

    /* ── Discovery: ask the server for its API roots, then its collections ──
     * Both endpoints are POST and expect the credentials of the form; an
     * older revision of this file wired them to DOMContentLoaded (which never
     * fires for a modal fragment) and posted a `baseurl` key they ignore. */
    var probeBtn = el('taxiiProbeBtn');
    var probeStatusEl = el('taxiiProbeStatus');
    var rootSelect = el('TaxiiServerApiRoot');
    var collectionSelect = el('TaxiiServerCollection');

    function setProbeStatus(kind, text) {
        if (!probeStatusEl) { return; }
        probeStatusEl.className = 'badge bg-' + kind;
        probeStatusEl.style.fontSize = '.65rem';
        probeStatusEl.textContent = text;
        probeStatusEl.classList.remove('d-none');
    }

    function credentials() {
        return {
            discovery_url: (el('TaxiiServerDiscoveryUrl') || {}).value || '',
            auth_type: authEl ? authEl.value : 'basic',
            username: (el('TaxiiServerUsername') || {}).value || '',
            password: (el('TaxiiServerPassword') || {}).value || '',
            api_key: (el('TaxiiServerApiKey') || {}).value || '',
            skip_proxy: el('TaxiiServerSkipProxy') && el('TaxiiServerSkipProxy').checked ? 1 : 0
        };
    }

    function post(action, body) {
        return fetch(BASE + '/taxii_servers/' + action + '.json', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': typeof getCsrfToken === 'function' ? getCsrfToken() : ''
            },
            body: JSON.stringify(body)
        }).then(function (r) { return r.json(); });
    }

    /* The endpoints answer {value: label}; keep the current pick if it survives */
    function fill(select, entries) {
        var previous = select.value;
        var ts = select.tomselect;
        var keys = Object.keys(entries || {});
        if (ts) {
            ts.clearOptions();
            keys.forEach(function (key) {
                ts.addOption({ value: key, text: entries[key] });
            });
            ts.refreshOptions(false);
            if (keys.indexOf(previous) !== -1) { ts.setValue(previous, true); }
        } else {
            select.innerHTML = '';
            keys.forEach(function (key) {
                var option = document.createElement('option');
                option.value = key;
                option.textContent = entries[key];
                if (key === previous) { option.selected = true; }
                select.appendChild(option);
            });
        }
        return keys.length;
    }

    function discover() {
        var creds = credentials();
        if (!creds.discovery_url.trim()) {
            setProbeStatus('warning', L.urlNeeded);
            return;
        }
        setProbeStatus('secondary', L.probing);
        post('getRoot', creds)
            .then(function (roots) {
                if (!roots || roots.errors || typeof roots !== 'object') {
                    throw new Error('getRoot');
                }
                var count = fill(rootSelect, roots);
                setProbeStatus('success', L.roots.replace('%s', count));
                if (!count) { return null; }
                var apiRoot = rootSelect.tomselect
                    ? rootSelect.tomselect.getValue() : rootSelect.value;
                var body = credentials();
                body.api_root = apiRoot;
                return post('getCollections', body);
            })
            .then(function (collections) {
                if (!collections) { return; }
                if (collections.errors || typeof collections !== 'object') {
                    throw new Error('getCollections');
                }
                var count = fill(collectionSelect, collections);
                setProbeStatus('success', L.collections.replace('%s', count));
            })
            .catch(function () { setProbeStatus('danger', L.probeFailed); });
    }

    if (probeBtn) { probeBtn.addEventListener('click', discover); }
    /* Picking another root reloads its collections */
    if (rootSelect) {
        rootSelect.addEventListener('change', function () {
            var body = credentials();
            body.api_root = rootSelect.value;
            if (!body.api_root) { return; }
            setProbeStatus('secondary', L.probing);
            post('getCollections', body)
                .then(function (collections) {
                    if (!collections || collections.errors) { throw new Error('getCollections'); }
                    setProbeStatus('success',
                        L.collections.replace('%s', fill(collectionSelect, collections)));
                })
                .catch(function () { setProbeStatus('danger', L.probeFailed); });
        });
    }

    /* ── Filters ── */
    var filtersEl = el('TaxiiServerFilters');
    var filtersStatusEl = el('taxiiFiltersStatus');
    var filtersErrorEl = el('taxiiFiltersError');

    function setFiltersStatus(kind, text) {
        if (!filtersStatusEl) { return; }
        filtersStatusEl.className = 'badge bg-' + kind;
        filtersStatusEl.style.fontSize = '.65rem';
        filtersStatusEl.textContent = text;
    }

    function setFiltersError(message) {
        if (!filtersErrorEl) { return; }
        if (!message) {
            filtersErrorEl.classList.add('d-none');
            filtersErrorEl.textContent = '';
            return;
        }
        filtersErrorEl.classList.remove('d-none');
        filtersErrorEl.innerHTML = '';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        filtersErrorEl.appendChild(icon);
        filtersErrorEl.appendChild(document.createTextNode(message));
    }

    function refreshFilters() {
        if (!filtersEl) { return; }
        var raw = filtersEl.value.trim();
        if (!raw) {
            setFiltersStatus('secondary', L.filtersEmpty);
            setFiltersError(null);
            return;
        }
        var parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            setFiltersStatus('danger', L.filtersInvalid);
            setFiltersError(e.message);
            return;
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            setFiltersStatus('danger', L.filtersInvalid);
            setFiltersError(L.objectExpected);
            return;
        }
        setFiltersStatus('success', L.filtersValid);
        setFiltersError(null);
    }

    if (filtersEl) { filtersEl.addEventListener('input', refreshFilters); }
    var filtersFormatBtn = el('taxiiFiltersFormatBtn');
    if (filtersFormatBtn) {
        filtersFormatBtn.addEventListener('click', function () {
            try {
                filtersEl.value = JSON.stringify(JSON.parse(filtersEl.value), null, 4);
            } catch (e) { /* refreshFilters() reports it */ }
            refreshFilters();
        });
    }

    /* ── Required fields ── */
    var nameEl = el('TaxiiServerName');
    var urlEl = el('TaxiiServerDiscoveryUrl');
    var form = el('taxiiServerForm');

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

    if (form) {
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
    }

    refreshAuth();
    refreshFilters();
})();
</script>
