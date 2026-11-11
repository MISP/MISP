<?php
$isEdit = $this->request->params['action'] === 'edit';

$server = $this->request->data['TaxiiServer'] ?? [];

$currentAuthType = $server['auth_type'] ?? 'basic';
$currentApiRoot = $server['api_root'] ?? '';
$currentCollection = $server['collection'] ?? '';

/* Stored minified; json_field pretty-prints it for editing. */
$filters = $server['filters'] ?? '';

$authTypes = ['basic' => __('Basic'), 'bearer' => __('Bearer')];

$options = [
    [
        'field' => 'enabled', 'id' => 'TaxiiServerEnabled',
        'label' => __('Enabled'),
        'hint' => __('Available as a push target'),
        'icon' => 'fas fa-power-off', 'accent' => 'var(--bs-success)',
        'checked' => $isEdit ? !empty($server['enabled']) : true,
    ],
    [
        'field' => 'skip_proxy', 'id' => 'TaxiiServerSkipProxy',
        'label' => __('Skip proxy'),
        'hint' => __('Reach it directly, ignoring the configured proxy'),
        'icon' => 'fas fa-diagram-project', 'accent' => 'var(--bs-secondary)',
        'checked' => !empty($server['skip_proxy']),
    ],
];

/* A rejected save re-renders this form: say why under the field. */
$serverError = function ($field) {
    if (!$this->Form->isFieldError($field)) {
        return '';
    }
    return sprintf(
        '<div class="ov-field-error"><i class="fas fa-circle-exclamation"></i><span>%s</span></div>',
        h(implode(' ', (array)($this->Form->validationErrors['TaxiiServer'][$field] ?? [])))
    );
};

echo $this->Form->create('TaxiiServer', [
    'id' => 'taxiiServerForm',
    'novalidate' => true,
    'data-required-guard' => '1',
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('TAXII Servers'),
    'title' => $isEdit ? __('Edit TAXII Server') : __('Add TAXII Server'),
    'description' => __('A TAXII 2.1 collection this instance can push STIX to — the discovery URL leads to the API roots.'),
    'icon' => 'fas fa-cloud',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Name'),
                'required' => true,
                'for' => 'TaxiiServerName',
            ]) ?>
            <?= $this->Form->text('name', [
                'id' => 'TaxiiServerName',
                'class' => 'ov-form-line fs-5'
                    . ($this->Form->isFieldError('name') ? ' is-invalid' : ''),
                'placeholder' => __('e.g. Partner TAXII collection'),
                'autocomplete' => 'off',
                'required' => true,
                'data-required-msg' => __('Please provide a name for the server.'),
            ]) ?>
            <?= $serverError('name') ?>
        </div>

        <!-- ── CONNECTION ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Connection'),
            ]) ?>

            <label class="form-label text-muted mb-1" for="TaxiiServerDiscoveryUrl"
                   style="font-size:.75rem;">
                <?= __('Discovery URL') ?>
            </label>
            <div class="input-group">
                <span class="input-group-text bg-transparent">
                    <i class="fas fa-link text-muted" style="font-size:.8rem;"></i>
                </span>
                <?= $this->Form->text('discovery_url', [
                    'id' => 'TaxiiServerDiscoveryUrl',
                    'class' => 'form-control font-monospace'
                        . ($this->Form->isFieldError('discovery_url') ? ' is-invalid' : ''),
                    'placeholder' => 'https://example.org/taxii2/',
                    'autocomplete' => 'off',
                ]) ?>
            </div>
            <?= $serverError('discovery_url') ?>

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
                        <span class="input-group-text bg-transparent">
                            <i class="fas fa-key text-muted" style="font-size:.8rem;"></i>
                        </span>
                        <?= $this->Form->text('api_key', [
                            'id' => 'TaxiiServerApiKey',
                            'type' => 'password',
                            'class' => 'form-control font-monospace',
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
            <div id="TaxiiServerAuthHint">
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => $currentAuthType === 'bearer'
                        ? __('The token is sent as an Authorization: Bearer header.')
                        : __('The username and password are stored as one encoded API key.'),
                ]) ?>
            </div>
        </div>

        <!-- ── TARGET COLLECTION ───────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => __('Target Collection'),
                    'class' => '',
                ]) ?>
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
            <div class="ov-field-error d-none" id="taxiiProbeError">
                <i class="fas fa-circle-exclamation"></i><span></span>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Discover asks the server for its API roots, then for the collections you may write to.'),
            ]) ?>
        </div>

        <!-- ── FILTERS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'filters',
                'label' => __('Filter Rules'),
                'shape' => 'object',
                'id' => 'TaxiiServerFilters',
                'value' => $filters,
                'rows' => 5,
                'minHeight' => '120px',
                'emptyLabel' => __('No filter'),
                'placeholder' => "{\n    \"tags\": [\"tlp:white\"],\n    \"published\": 1\n}",
                'hint' => __('A restsearch filter object — it decides which events are pushed.'),
            ]) ?>
        </div>

        <!-- ── OWNER / DESCRIPTION ─────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Bookkeeping'),
            ]) ?>
            <div class="row g-3">
                <div class="col-md-6">
                    <label class="form-label text-muted mb-1" for="TaxiiServerOwner"
                           style="font-size:.75rem;">
                        <?= __('Owner') ?>
                    </label>
                    <?= $this->Form->text('owner', [
                        'id' => 'TaxiiServerOwner',
                        'class' => 'form-control',
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
                        'placeholder' => __('What is pushed there…'),
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Options'),
            ]) ?>
            <div class="row g-2">
                <?php foreach ($options as $option): ?>
                    <div class="col-md-6">
                        <label class="d-flex align-items-center gap-3 rounded-2 p-3
                                      h-100 w-100 user-select-none mb-0"
                               data-option-card
                               data-accent="<?= h($option['accent']) ?>"
                               style="cursor:pointer; transition:border-color .15s;
                                      border:1px solid <?= $option['checked']
                                          ? h($option['accent']) : 'var(--bs-border-color)' ?>;">
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
                                          ? h($option['accent']) : 'var(--bs-secondary-color)' ?>;"></i>
                        </label>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'primary',
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('Server'), 'id' => $id]] : [],
        'hint' => __('Basic credentials are stored as the encoded API key.'),
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Server')],
    ]) ?>

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
        urlScheme: <?= json_encode(__('The URL has to start with http:// or https://')) ?>
    };

    function el(id) { return document.getElementById(id); }

    /* ── Option cards ── */
    function paintCard(card) {
        var box = card.querySelector('input[type="checkbox"]');
        var icon = card.querySelector('[data-option-icon]');
        var accent = card.dataset.accent || 'var(--bs-primary)';
        if (!box) { return; }
        card.style.borderColor = box.checked ? accent : 'var(--bs-border-color)';
        if (icon) {
            icon.style.color = box.checked ? accent : 'var(--bs-secondary-color)';
        }
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
            node.classList.toggle('d-none', !isBasic);
        });
        document.querySelectorAll('.taxii-auth-bearer').forEach(function (node) {
            node.classList.toggle('col-md-8', !isBasic);
            node.classList.toggle('col-md-4', isBasic);
        });
        if (apiKeyLabel) {
            apiKeyLabel.textContent = isBasic ? L.basicLabel : L.bearerLabel;
        }
        var hint = authHintEl ? authHintEl.querySelector('div') : null;
        if (hint && hint.lastChild) {
            hint.lastChild.textContent = ' ' + (isBasic ? L.basicHint : L.bearerHint);
        }
    }
    if (authEl) { authEl.addEventListener('change', refreshAuth); }

    /* ── Discovery: ask the server for its API roots, then its collections ── */
    var probeBtn = el('taxiiProbeBtn');
    var probeStatusEl = el('taxiiProbeStatus');
    var probeErrorEl = el('taxiiProbeError');
    var rootSelect = el('TaxiiServerApiRoot');
    var collectionSelect = el('TaxiiServerCollection');

    function setProbeStatus(kind, text) {
        if (!probeStatusEl) { return; }
        probeStatusEl.className = 'badge bg-' + kind;
        probeStatusEl.style.fontSize = '.65rem';
        probeStatusEl.textContent = text;
        probeStatusEl.classList.remove('d-none');
    }

    function setProbeError(message) {
        if (!probeErrorEl) { return; }
        probeErrorEl.querySelector('span').textContent = message || '';
        probeErrorEl.classList.toggle('d-none', !message);
    }

    function probeFailed(err) {
        setProbeStatus('danger', L.probeFailed);
        setProbeError(err && err.message);
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

    /* Some refusals arrive already HTML-escaped (the URL egress check). */
    function plain(text) {
        var doc = new DOMParser().parseFromString(String(text), 'text/html');
        return doc.documentElement.textContent;
    }

    /* A failure is any non-2xx answer: not every one carries an `errors` key,
       and one that does not must never be read as a {value: label} map. */
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
        }).then(function (r) {
            return r.json().catch(function () { return null; }).then(function (data) {
                if (r.ok && data && typeof data === 'object' && !data.errors) {
                    return data;
                }
                var reason = data && (data.errors || data.message || data.name);
                if (reason && typeof reason === 'object') {
                    reason = Object.values(reason).join(' ');
                }
                throw new Error(reason ? plain(reason) : 'HTTP ' + r.status);
            });
        });
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

    function loadCollections(apiRoot) {
        var body = credentials();
        body.api_root = apiRoot;
        return post('getCollections', body).then(function (collections) {
            setProbeStatus('success',
                L.collections.replace('%s', fill(collectionSelect, collections)));
        });
    }

    function discover() {
        var creds = credentials();
        setProbeError('');
        if (!creds.discovery_url.trim()) {
            setProbeStatus('warning', L.urlNeeded);
            return;
        }
        setProbeStatus('secondary', L.probing);
        post('getRoot', creds)
            .then(function (roots) {
                var count = fill(rootSelect, roots);
                setProbeStatus('success', L.roots.replace('%s', count));
                if (!count) { return null; }
                return loadCollections(rootSelect.tomselect
                    ? rootSelect.tomselect.getValue() : rootSelect.value);
            })
            .catch(probeFailed);
    }

    if (probeBtn) { probeBtn.addEventListener('click', discover); }
    /* Picking another root reloads its collections */
    if (rootSelect) {
        rootSelect.addEventListener('change', function () {
            if (!rootSelect.value) { return; }
            setProbeError('');
            setProbeStatus('secondary', L.probing);
            loadCollections(rootSelect.value).catch(probeFailed);
        });
    }

    /* The name is refused empty by the page's required-field guard, and the
       filters by their json_field; only the URL's scheme is checked here. */
    var urlEl = el('TaxiiServerDiscoveryUrl');
    var urlGroup = urlEl ? urlEl.closest('.input-group') : null;
    var urlError = null;

    function setUrlError(message) {
        urlEl.classList.toggle('is-invalid', !!message);
        if (!message) {
            if (urlError) { urlError.remove(); urlError = null; }
            return;
        }
        if (!urlError) {
            urlError = document.createElement('div');
            urlError.className = 'ov-field-error';
            urlError.innerHTML = '<i class="fas fa-circle-exclamation"></i><span></span>';
            urlGroup.parentNode.insertBefore(urlError, urlGroup.nextSibling);
        }
        urlError.querySelector('span').textContent = message;
    }

    var form = el('taxiiServerForm');
    if (form && urlEl && urlGroup) {
        form.addEventListener('submit', function (e) {
            var url = urlEl.value.trim();
            if (url && !/^https?:\/\//i.test(url)) {
                setUrlError(L.urlScheme);
                e.preventDefault();
                urlEl.focus();
            }
        });
        urlEl.addEventListener('input', function () {
            var url = urlEl.value.trim();
            if (!url || /^https?:\/\//i.test(url)) { setUrlError(null); }
        });
    }

    refreshAuth();
})();
</script>
