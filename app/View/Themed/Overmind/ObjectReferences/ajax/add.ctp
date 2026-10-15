<?php
App::uses('CakeNumber', 'Utility');
/*
 * GET /objectReferences/add/{objectId}: one relationship from this object.
 * Targets are searched through /objectReferences/targets/{eventId}.
 */
$objectId = (int)$object['Object']['id'];
$eventId = (int)$object['Event']['id'];
$config = [
    'addUrl' => $baseurl . '/objectReferences/add/' . $objectId,
    'targetsUrl' => $baseurl . '/objectReferences/targets/' . $eventId,
    'selfUuid' => $object['Object']['uuid'],
    'defaultType' => 'related-to',
    'messages' => [
        'failed' => __('The relationship could not be added.'),
        'request' => __('Request failed — please try again.'),
        'saved' => __('Relationship added.'),
        'choices' => __('Could not load the relationship choices.'),
        'search' => __('Search the event, or paste a UUID'),
        'uuid' => __('Use this UUID'),
        'hint' => __('Type at least 3 characters, or paste a UUID.'),
        'windowed' => __(
            'Searched the newest %s objects and attributes of this event. Paste the UUID of an older one.',
            CakeNumber::format(ObjectReferencesController::TARGET_SEARCH_WINDOW)
        ),
    ],
];
?>
<form id="objRefAddForm" novalidate>
<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'object',
    'eyebrow' => __('%s · object #%s', $object['Object']['name'], $objectId),
    'title' => __('Add a relationship'),
    'titleIcon' => 'fas fa-link',
    'description' => __('Point this object at another object or attribute.'),
    'icon' => 'fas fa-diagram-project',
]) ?>

<div class="container-fluid px-4 py-4">
    <div class="row g-4">
        <div class="col-md-5">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Relationship type'),
                'required' => true,
                'for' => 'objRefAddType',
            ]) ?>
            <select id="objRefAddType" class="form-select" aria-label="<?= h(__('Relationship type')) ?>"></select>
            <input type="text" id="objRefAddCustom" class="form-control mt-2 d-none"
                   placeholder="<?= h(__('Custom relationship type')) ?>"
                   aria-label="<?= h(__('Custom relationship type')) ?>">
        </div>
        <div class="col-md-7">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Target'),
                'required' => true,
                'for' => 'objRefAddTarget',
            ]) ?>
            <select id="objRefAddTarget" aria-label="<?= h(__('Target')) ?>" aria-describedby="objRefAddHint"></select>
            <div class="form-text" id="objRefAddHint"></div>
        </div>
        <div class="col-12">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Comment'),
                'for' => 'objRefAddComment',
            ]) ?>
            <textarea id="objRefAddComment" class="form-control" rows="2"></textarea>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'object',
        'submit' => [
            'label' => __('Add relationship'),
            'icon' => 'fas fa-link',
            'id' => 'objRefAddSubmit',
        ],
    ]) ?>
</div>
</form>

<script type="application/json" id="objRefAddConfig"><?= json_encode(
    $config, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
) ?></script>
<script>
(function () {
    var form = document.getElementById('objRefAddForm');
    var cfg = JSON.parse(document.getElementById('objRefAddConfig').textContent);
    var typeEl = document.getElementById('objRefAddType');
    var customEl = document.getElementById('objRefAddCustom');
    var targetEl = document.getElementById('objRefAddTarget');
    var commentEl = document.getElementById('objRefAddComment');
    var submitBtn = document.getElementById('objRefAddSubmit');
    var uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    var hintEl = document.getElementById('objRefAddHint');
    var targetSelect;
    hintEl.textContent = cfg.messages.hint;

    function withoutSelf(targets) {
        return (targets || []).filter(function (t) { return t.uuid !== cfg.selfUuid; });
    }

    function relationshipType() {
        return typeEl.value === 'custom' ? customEl.value.trim() : typeEl.value;
    }

    function sync() {
        customEl.classList.toggle('d-none', typeEl.value !== 'custom');
        submitBtn.disabled = !(relationshipType() && targetEl.value);
    }

    function fetchTargets(query) {
        var url = cfg.targetsUrl + (query ? '?searchTerm=' + encodeURIComponent(query) : '');
        return fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.json(); });
    }

    submitBtn.disabled = true;
    fetchTargets('').then(function (res) {
        (res.relationships || []).forEach(function (name) {
            typeEl.add(new Option(name, name, false, name === cfg.defaultType));
        });
        new TomSelect(typeEl, { create: false, onChange: function () {
            sync();
            if (typeEl.value === 'custom') { customEl.focus(); }
        } });
        targetSelect = new TomSelect(targetEl, Object.assign({
            valueField: 'uuid',
            labelField: 'label',
            searchField: ['label', 'context', 'uuid'],
            options: withoutSelf(res.targets),
            placeholder: cfg.messages.search,
            create: function (input) {
                return uuidPattern.test(input.trim())
                    ? { uuid: input.trim(), label: input.trim(), kind: 'uuid', context: '' }
                    : false;
            },
            createFilter: function (input) { return uuidPattern.test(input.trim()); },
        }, referenceTargetSearch(cfg.targetsUrl, withoutSelf, function (res) {
            hintEl.textContent = res.windowed ? cfg.messages.windowed : cfg.messages.hint;
        }), {
            render: {
                option: function (item, escape) {
                    return '<div class="py-1">'
                        + '<span class="badge bg-secondary me-1">' + escape(item.kind) + '</span>'
                        + '<span class="text-break">' + escape(item.label) + '</span>'
                        + (item.context ? '<div class="text-muted small">' + escape(item.context) + '</div>' : '')
                        + '</div>';
                },
                item: function (item, escape) {
                    return '<div class="text-truncate">' + escape(item.label) + '</div>';
                },
                option_create: function (data, escape) {
                    return '<div class="create py-1"><i class="fas fa-fingerprint me-1"></i>'
                        + escape(cfg.messages.uuid) + ': <code>' + escape(data.input) + '</code></div>';
                }
            },
            onChange: sync
        }));
        sync();
    }).catch(function () {
        showToast(cfg.messages.choices, 'danger');
    });

    customEl.addEventListener('input', sync);

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (submitBtn.disabled) { return; }
        submitBtn.disabled = true;
        var body = new URLSearchParams();
        body.set('data[ObjectReference][referenced_uuid]', targetEl.value);
        body.set('data[ObjectReference][relationship_type]', relationshipType());
        body.set('data[ObjectReference][comment]', commentEl.value.trim());
        fetch(cfg.addUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': getCsrfToken()
            },
            body: body.toString()
        })
            .then(function (r) { return r.ok ? r.json() : { saved: false }; })
            .then(function (res) {
                if (!res || !res.saved) {
                    showToast((res && res.errors) || cfg.messages.failed, 'danger');
                    sync();
                    return;
                }
                bootstrap.Modal.getInstance(document.getElementById('mainModal')).hide();
                showToast(cfg.messages.saved, 'success');
                reloadEventViewIndexTab();
            })
            .catch(function () {
                showToast(cfg.messages.request, 'danger');
                sync();
            });
    });
}());
</script>
