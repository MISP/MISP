<?php
$isEdit = $this->request->params['action'] === 'editWithTags';

App::uses('IndexPicker', 'Tools');

$collection = $this->request->data['TagCollection'] ?? [];
$currentTags = $currentTags ?? [];
$currentClusters = $currentClusters ?? [];

// Both lists are posted from hidden inputs the picker below writes.
$this->Form->unlockField('TagCollection.tags');
$this->Form->unlockField('TagCollection.galaxies');
$browsers = [
    'tag' => [
        'scopes' => $baseurl . '/tags/pickerScopes',
        'source' => $baseurl . '/tags/pickerSearch',
        'tree' => $baseurl . '/tags/pickerTree',
        'label' => __('Tags'),
        'accent' => 'var(--bs-tag)',
    ],
    'galaxy' => [
        'scopes' => $baseurl . '/galaxies/pickerScopes',
        'source' => $baseurl . '/galaxy_clusters/pickerSearch',
        'label' => __('Galaxy clusters'),
        'accent' => 'var(--bs-galaxy)',
    ],
];
$sideHead = 'd-flex align-items-center gap-2 fw-bold text-uppercase mb-2';
$sideHeadStyle = 'font-size:.65rem; letter-spacing:.1em;';

// Opened directly rather than as a modal: the form's own header strip titles the page
$asPage = empty($ajax);
if ($asPage) {
    $this->set('hideHeaderSection', true);
    echo '<div class="container-xl py-4"><div class="card shadow-sm overflow-hidden">';
}

echo $this->Form->create('TagCollection', [
    'id' => 'tagCollectionForm',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Tag Collections'),
    'title' => $isEdit ? __('Edit Tag Collection') : __('Add Tag Collection'),
    'description' => __('A collection groups the tags and galaxy clusters that are usually applied together, so they can be attached in one go.'),
    'icon' => 'fas fa-layer-group',
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-accent fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Collection Name') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'TagCollectionName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid var(--misp-field-line, #d8dde3) !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. Phishing triage set'),
                'autocomplete' => 'off',
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'rows' => 2,
                'style' => 'border-color:var(--misp-field-line, #d8dde3);',
                'placeholder' => __('What this set of tags is for…'),
            ]) ?>
        </div>

        <!-- ── TAGS AND GALAXY CLUSTERS ────────────────────────── -->
        <div class="w-100 px-2 d-flex flex-column gap-3" id="tag-collection-picker">
            <div class="btn-group btn-group-sm align-self-start" role="group"
                 aria-label="<?= __('What to browse') ?>">
                <button type="button" class="btn btn-outline-tag active" data-kind="tag" aria-pressed="true">
                    <i class="fas fa-tags me-1"></i><?= __('Tags') ?>
                </button>
                <button type="button" class="btn btn-outline-galaxy" data-kind="galaxy" aria-pressed="false">
                    <span class="misp-icon misp-icon-galaxy misp-simple me-1"></span><?= __('Galaxy clusters') ?>
                </button>
            </div>

            <div class="ifb-accented" style="--ifb-accent: var(--bs-tag);" data-browser-host>
                <div class="text-center py-5 text-body-secondary">
                    <div class="misp-loader misp-loader-sm" role="status"></div>
                </div>
            </div>

            <div data-side="tag">
                <div class="<?= $sideHead ?> text-tag" style="<?= $sideHeadStyle ?>">
                    <i class="fas fa-tags"></i>
                    <?= __('Tags') ?>
                    <span class="fw-normal text-body-secondary" data-side-count></span>
                </div>
                <div class="d-flex flex-wrap" data-side-list></div>
                <div class="text-muted small fst-italic" data-side-empty><?= __('No tags in this collection yet.') ?></div>
            </div>
            <div data-side="galaxy">
                <div class="<?= $sideHead ?> text-galaxy" style="<?= $sideHeadStyle ?>">
                    <span class="misp-icon misp-icon-galaxy misp-simple"></span>
                    <?= __('Galaxy clusters') ?>
                    <span class="fw-normal text-body-secondary" data-side-count></span>
                </div>
                <div class="d-flex flex-wrap gap-2" data-side-list></div>
                <div class="text-muted small fst-italic" data-side-empty><?= __('No galaxy clusters in this collection yet.') ?></div>
            </div>

            <div class="d-none" data-inputs></div>
        </div>

        <!-- ── VISIBILITY ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Visibility'),
            ]) ?>
            <?php $allOrgs = !empty($collection['all_orgs']); ?>
            <label class="d-flex align-items-center gap-3 rounded-2 p-3 w-100
                          user-select-none mb-0"
                   id="TagCollectionAllOrgsCard"
                   style="cursor:pointer; transition:border-color .15s;
                          border:1px solid <?= $allOrgs ? 'var(--bs-primary)' : 'var(--misp-check-off-line, #dee2e6)' ?>;">
                <?= $this->Form->checkbox('all_orgs', [
                    'id' => 'TagCollectionAllOrgs',
                    'class' => 'form-check-input flex-shrink-0',
                    'style' => 'margin-top:0;',
                    'checked' => $allOrgs,
                ]) ?>
                <div class="flex-fill">
                    <div class="fw-bold text-uppercase"
                         style="font-size:.72rem; letter-spacing:.06em;
                                line-height:1.2;">
                        <?= __('Visible to all organisations') ?>
                    </div>
                    <div class="text-muted"
                         style="font-size:.76rem; margin-top:.2rem; line-height:1.3;">
                        <?= __('Left off, only your own organisation sees this collection.') ?>
                    </div>
                </div>
                <i class="fas fa-globe" id="TagCollectionAllOrgsIcon"
                   style="font-size:.95rem; transition:color .15s;
                          color:<?= $allOrgs ? 'var(--bs-primary)' : 'var(--misp-check-off-icon, #adb5bd)' ?>;"></i>
            </label>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($collection['id']) ? [['label' => __('Collection'), 'id' => $collection['id']]] : [],
        'cancel' => $asPage ? ['href' => $baseurl . '/tagCollections/index', 'attrs' => []] : [],
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Collection')],
    ]) ?>

</div>

<?= $this->Form->end() ?>
<?php if ($asPage): ?>
</div></div>
<?php endif; ?>

<script>
/*
 * Tags and galaxy clusters are picked in the column browser of the index
 * filter bars (index-filter-browser.js). A page holds one browser, so a switch
 * shows one kind at a time; both lists stay below it.
 */
(function () {
    var asPage   = <?= json_encode($asPage) ?>;
    var browsers = <?= json_encode($browsers, JSON_HEX_TAG | JSON_HEX_AMP) ?>;
    var strings  = <?= json_encode(IndexPicker::browserStrings(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE) ?>;
    var assets   = <?= $this->element('genericElementsBS5/Modals/index_filter_browser_assets') ?>;
    var labels   = <?= json_encode([
        'remove' => __('Remove'),
        'showWhere' => __('Show where it lives'),
        'loadFailed' => __('The browser could not be loaded.'),
    ], JSON_HEX_TAG | JSON_HEX_AMP) ?>;
    var inputNames = { tag: 'data[TagCollection][tags]', galaxy: 'data[TagCollection][galaxies]' };

    /* Tag name => entry, per kind: tags {id, name, colour}, clusters {id, name, galaxy, hue, tag_name}. */
    var picked = { tag: {}, galaxy: {} };
    (<?= json_encode($currentTags, JSON_HEX_TAG | JSON_HEX_AMP) ?: '[]' ?>).forEach(function (t) {
        picked.tag[t.name] = t;
    });
    (<?= json_encode($currentClusters, JSON_HEX_TAG | JSON_HEX_AMP) ?: '[]' ?>).forEach(function (c) {
        picked.galaxy[c.tag_name] = c;
    });

    var root = document.getElementById('tag-collection-picker');
    var host = root.querySelector('[data-browser-host]');
    var kind = 'tag';
    var browser = null;

    function selection() {
        return Object.keys(picked[kind]).map(function (tag) { return { value: tag }; });
    }

    function writeInputs() {
        var box = root.querySelector('[data-inputs]');
        box.innerHTML = '';
        ['tag', 'galaxy'].forEach(function (k) {
            // The empty scalar first: an emptied list still posts, and clears the collection's.
            [''].concat(Object.keys(picked[k]).map(function (tag) { return picked[k][tag].id; })).forEach(function (id, i) {
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = inputNames[k] + (i ? '[]' : '');
                input.value = id;
                box.appendChild(input);
            });
        });
    }

    function removeButton(onClick) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'hg-act';
        b.title = labels.remove;
        b.setAttribute('aria-label', labels.remove);
        b.innerHTML = '&times;';
        b.addEventListener('click', function (e) {
            e.stopPropagation();
            onClick();
        });
        return b;
    }

    function renderLists() {
        ['tag', 'galaxy'].forEach(function (k) {
            var box = root.querySelector('[data-side="' + k + '"]');
            var list = Object.keys(picked[k]).map(function (tag) { return picked[k][tag]; })
                .sort(function (a, b) { return a.name.localeCompare(b.name); });
            var byId = {};
            list.forEach(function (e) { byId[e.id] = e; });
            box.querySelector('[data-side-count]').textContent = list.length ? '(' + list.length + ')' : '';
            box.querySelector('[data-side-empty]').classList.toggle('d-none', list.length > 0);
            var el = box.querySelector('[data-side-list]');
            el.innerHTML = k === 'tag'
                ? TagChips.collection(list.map(function (t) {
                    return { id: t.id, name: t.name, colour: t.colour };
                }), { searchUrl: '' })
                : TagChips.clusters(list.map(function (c) {
                    return { id: c.id, value: c.name, galaxy: c.galaxy, hue: c.hue };
                }), { href: function () { return null; } });
            el.querySelectorAll('.hg-unit').forEach(function (unit) {
                var ref = k === 'tag' ? unit.querySelector('[data-tag-id]') : unit;
                var e = ref ? byId[ref.getAttribute(k === 'tag' ? 'data-tag-id' : 'data-cluster-id')] : null;
                if (!e) { return; }
                var tagName = k === 'tag' ? e.name : e.tag_name;
                unit.title = labels.showWhere;
                unit.style.cursor = 'pointer';
                unit.addEventListener('click', function (ev) {
                    ev.preventDefault();
                    show(k);
                    if (browser) { browser.reveal(tagName); }
                });
                unit.appendChild(removeButton(function () {
                    delete picked[k][tagName];
                    changed();
                }));
            });
        });
        writeInputs();
    }

    function changed() {
        renderLists();
        if (browser) { browser.select(selection()); }
    }

    function onToggle(row, on) {
        if (!on) {
            delete picked[kind][row.value];
        } else if (kind === 'tag') {
            picked.tag[row.value] = {
                id: row.id,
                name: row.value,
                colour: row.style && row.style.colour ? row.style.colour : '#0088cc'
            };
        } else {
            picked.galaxy[row.value] = {
                id: row.id,
                name: row.label,
                galaxy: row.style && row.style.galaxy ? row.style.galaxy : '',
                tag_name: row.value
            };
        }
        changed();
    }

    /* Draws the browser of one kind, in that kind's colour. */
    function show(next) {
        if (browser && next === kind) { return; }
        kind = next;
        root.querySelectorAll('[data-kind]').forEach(function (btn) {
            var on = btn.getAttribute('data-kind') === kind;
            btn.classList.toggle('active', on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        if (!window.IndexFilterBrowser || !window.IndexFilterBrowser.mount) { return; }
        if (browser) { browser.destroy(); }
        host.innerHTML = '';
        host.style.setProperty('--ifb-accent', browsers[kind].accent);
        browser = window.IndexFilterBrowser.mount(host, {
            kind: kind,
            scopes: browsers[kind].scopes,
            source: browsers[kind].source,
            tree: browsers[kind].tree,
            label: browsers[kind].label,
            strings: strings,
            selection: selection(),
            onToggle: onToggle,
            reserve: 600
        });
    }

    function boot() {
        root.querySelectorAll('[data-kind]').forEach(function (btn) {
            btn.addEventListener('click', function () { show(btn.getAttribute('data-kind')); });
        });
        renderLists();
        loadIndexFilterBrowser(assets).then(function () {
            if (root.isConnected) { show(kind); }
        }, function () {
            host.innerHTML = '<div class="text-center py-4 text-body-secondary small">'
                + '<i class="fas fa-triangle-exclamation me-2"></i></div>';
            host.firstChild.appendChild(document.createTextNode(labels.loadFailed));
        });
        // In a modal the browser goes with it; on its own page it stays.
        var modalEl = document.getElementById('mainModal');
        if (!asPage && modalEl) {
            modalEl.addEventListener('hidden.bs.modal', function () {
                if (browser) { browser.destroy(); }
            }, { once: true });
        }
    }

    /* On a full page this runs before mispOvermind.js defines the loader */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();

(function () {
    var NAME_REQUIRED =<?= json_encode(__('Please provide a name for the collection.')) ?>;

    /* Visibility card follows its checkbox, like the option cards in Tags/add */
    var allOrgsBox = document.getElementById('TagCollectionAllOrgs');
    var allOrgsCard = document.getElementById('TagCollectionAllOrgsCard');
    var allOrgsIcon = document.getElementById('TagCollectionAllOrgsIcon');
    if (allOrgsBox && allOrgsCard) {
        allOrgsBox.addEventListener('change', function () {
            allOrgsCard.style.setProperty('border-color',
                allOrgsBox.checked ? 'var(--bs-primary)' : 'var(--misp-check-off-line, #dee2e6)');
            if (allOrgsIcon) {
                allOrgsIcon.style.setProperty('color',
                    allOrgsBox.checked ? 'var(--bs-primary)' : 'var(--misp-check-off-icon, #adb5bd)');
            }
        });
    }

    var nameEl = document.getElementById('TagCollectionName');
    var form = document.getElementById('tagCollectionForm');
    if (form && nameEl) {
        var errorId = 'tagCollectionNameError';

        form.addEventListener('submit', function (e) {
            if (nameEl.value.trim()) { return; }
            e.preventDefault();
            e.stopPropagation();
            nameEl.style.setProperty('border-bottom-color', 'var(--misp-tone-red-solid, #dc3545)', 'important');
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
            nameEl.focus();
        });

        nameEl.addEventListener('input', function () {
            if (!nameEl.value.trim()) { return; }
            nameEl.style.setProperty('border-bottom-color', 'var(--misp-field-line, #d8dde3)', 'important');
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
        });
    }
})();
</script>
