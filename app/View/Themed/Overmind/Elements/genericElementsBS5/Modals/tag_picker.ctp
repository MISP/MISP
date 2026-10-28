<?php
/*
 * Modal to pick global/local tags for an object.
 *
 * The tags are picked in the column browser of the index filter bars
 * (index-filter-browser.js, mounted here), which also offers the reader's tag
 * collections: a pick is global (local for a local-only tag), and its chip in
 * the lists below the browser moves it to the other side.
 *
 * Required params:
 *   $saveUrl           string  POST target (unescaped, h()'d here)
 *   $uid               string  unique DOM/scope id (e.g. 'evt-tags-12')
 *   $tagCollections    [{id, name, tags: [{id, name, colour, local_only}]}, ...]
 *   $currentGlobalTags [{id, name, colour, local_only, tag_name}, ...]  pre-selected (global)
 *   $currentLocalTags  [{id, name, colour, local_only, tag_name}, ...]  pre-selected (local)
 *   $mayModify         bool
 * Optional params:
 *   $headerEyebrow     string  small uppercase label (default "Tags")
 *   $title             string  modal title (default "Edit Tags")
 *   $description       string  one line under the title
 *   $saveLabel         string  submit label (default "Save Tags")
 *   $reloadHook        string  window['<hook>' + uid] fn called after save;
 *                              falls back to the attribute-index reload.
 *   $openTaxonomy      string  namespace of the taxonomy the browser opens on
 *
 * `tag_name` is optional: the tag itself, when `name` says more (the mass
 * edit's "· 2/5").
 *
 * A save announces itself as `misp:tags-saved` ({uid}) on the document.
 */
App::uses('IndexPicker', 'Tools');

$headerEyebrow = $headerEyebrow ?? __('Tags');
$reloadHook    = $reloadHook ?? '';

$postUrl   = h($saveUrl);

$initGJson = json_encode($currentGlobalTags, JSON_HEX_TAG | JSON_HEX_AMP);
$initLJson = json_encode($currentLocalTags,  JSON_HEX_TAG | JSON_HEX_AMP);

$browser = [
    'scopes'      => $baseurl . '/tags/pickerScopes',
    'source'      => $baseurl . '/tags/pickerSearch',
    'tree'        => $baseurl . '/tags/pickerTree',
    'label'       => __('Tags'),
    'strings'     => IndexPicker::browserStrings(),
    'collections' => $tagCollections,
    'open'        => $openTaxonomy ?? null,
];

$sideHead = 'd-flex align-items-center gap-2 fw-bold text-uppercase mb-2 text-tag';
$sideHeadStyle = 'font-size:.65rem; letter-spacing:.1em;';
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'tag',
    'eyebrow' => $headerEyebrow,
    'title' => $title ?? __('Edit Tags'),
    'titleIcon' => 'fas fa-pen-to-square',
    'description' => $description ?? '',
    'icon' => 'misp-icon misp-icon-tag misp-simple',
]) ?>

<div class="container-fluid px-4 py-4" id="<?= h($uid) ?>-picker">

    <div class="d-flex flex-column gap-3">

        <div class="ifb-accented" style="--ifb-accent: var(--bs-tag);" data-browser-host>
            <div class="text-center py-5 text-body-secondary">
                <div class="misp-loader misp-loader-sm" role="status"></div>
            </div>
        </div>

        <div class="d-flex flex-column gap-3">
            <div data-side="global">
                <div class="<?= $sideHead ?>" style="<?= $sideHeadStyle ?>">
                    <i class="fas fa-globe"></i>
                    <?= __('Global Tags') ?>
                    <span class="fw-normal text-body-secondary" data-side-count></span>
                </div>
                <div class="d-flex flex-wrap" data-side-list></div>
                <div class="text-muted small fst-italic" data-side-empty><?= __('No tags selected.') ?></div>
            </div>
            <div data-side="local">
                <div class="<?= $sideHead ?>" style="<?= $sideHeadStyle ?>">
                    <i class="fas fa-user"></i>
                    <?= __('Local Tags') ?>
                    <span class="fw-normal text-body-secondary" data-side-count></span>
                    <span class="badge bg-warning text-dark fw-normal" style="font-size:.6rem; text-transform:none; letter-spacing:0;">
                        <?= __('Would not be synchronized with other instances') ?>
                    </span>
                </div>
                <div class="d-flex flex-wrap" data-side-list></div>
                <div class="text-muted small fst-italic" data-side-empty><?= __('No tags selected.') ?></div>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'tag',
        'align' => 'end',
        'submit' => $mayModify ? [
            'label' => $saveLabel ?? __('Save Tags'),
            'icon' => 'fas fa-save',
            'id' => 'edit-tags-save-btn',
            'type' => 'button',
        ] : false,
    ]) ?>

</div>

<script>
    var postUrl    = <?= json_encode($postUrl) ?>;
    var uid        = <?= json_encode($uid) ?>;
    var reloadHook = <?= json_encode($reloadHook) ?>;
    var browserCfg = <?= json_encode($browser, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE) ?>;
    var browserAssets = <?= $this->element('genericElementsBS5/Modals/index_filter_browser_assets') ?>;
    var root       = document.getElementById(uid + '-picker');
    var modalEl    = document.getElementById('mainModal');
    var labels     = <?= json_encode([
        'makeLocal' => __('Make it local'),
        'makeGlobal' => __('Make it global'),
        'localOnly' => __('This tag can only be attached locally'),
        'remove' => __('Remove'),
        'showWhere' => __('Show where it lives'),
        'loadFailed' => __('The tag browser could not be loaded.'),
    ], JSON_HEX_TAG | JSON_HEX_AMP) ?>;

    /* Tag name => {id, name, colour, local_only, tag_name}, per side. A mass edit can carry one tag on both. */
    var picked = { global: {}, local: {} };
    [['global', <?= $initGJson ?: '[]' ?>], ['local', <?= $initLJson ?: '[]' ?>]].forEach(function (side) {
        side[1].forEach(function (t) {
            t.tag_name = t.tag_name || t.name;
            picked[side[0]][t.tag_name] = t;
        });
    });
    var browser = null;

    function entries(side) {
        return Object.keys(picked[side]).map(function (tag) { return picked[side][tag]; });
    }

    /* What the browser ticks: a tag on both sides shows as global. */
    function browserSelection() {
        var out = Object.keys(picked.global).map(function (tag) { return { value: tag }; });
        Object.keys(picked.local).forEach(function (tag) {
            if (!picked.global[tag]) { out.push({ value: tag, local: true }); }
        });
        return out;
    }

    function chipButton(icon, title, onClick) {
        var b = document.createElement('button');
        b.type = 'button';
        b.className = 'hg-act';
        b.title = title;
        b.setAttribute('aria-label', title);
        b.innerHTML = icon;
        b.addEventListener('click', function (e) {
            e.stopPropagation();
            onClick();
        });
        return b;
    }

    function renderSides() {
        ['global', 'local'].forEach(function (side) {
            var box = root.querySelector('[data-side="' + side + '"]');
            var other = side === 'global' ? 'local' : 'global';
            var list = entries(side).sort(function (a, b) { return a.name.localeCompare(b.name); });
            var byId = {};
            list.forEach(function (t) { byId[t.id] = t; });
            box.querySelector('[data-side-count]').textContent = list.length ? '(' + list.length + ')' : '';
            box.querySelector('[data-side-empty]').classList.toggle('d-none', list.length > 0);
            var el = box.querySelector('[data-side-list]');
            el.innerHTML = TagChips.collection(list.map(function (t) {
                return { id: t.id, name: t.name, colour: t.colour, local: side === 'local' };
            }), { searchUrl: '' });
            el.querySelectorAll('.hg-unit').forEach(function (unit) {
                var chip = unit.querySelector('[data-tag-id]');
                var t = chip ? byId[chip.getAttribute('data-tag-id')] : null;
                if (!t) { return; }
                unit.title = labels.showWhere;
                unit.style.cursor = 'pointer';
                unit.addEventListener('click', function (e) {
                    e.preventDefault();
                    if (browser) { browser.reveal(t.tag_name); }
                });
                if (t.local_only && side === 'local') {
                    unit.title = labels.localOnly;
                } else {
                    unit.appendChild(chipButton(
                        '<i class="fas ' + (side === 'global' ? 'fa-user' : 'fa-globe') + '"></i>',
                        side === 'global' ? labels.makeLocal : labels.makeGlobal,
                        function () {
                            delete picked[side][t.tag_name];
                            if (!picked[other][t.tag_name]) { picked[other][t.tag_name] = t; }
                            changed();
                        }
                    ));
                }
                unit.appendChild(chipButton('&times;', labels.remove, function () {
                    delete picked[side][t.tag_name];
                    changed();
                }));
            });
        });
    }

    function changed() {
        renderSides();
        if (browser) { browser.select(browserSelection()); }
    }

    function pick(t) {
        if (picked.global[t.tag_name] || picked.local[t.tag_name]) { return; }
        picked[t.local_only ? 'local' : 'global'][t.tag_name] = t;
    }

    /* A collection row adds its tags, or removes them all once each is picked. */
    function onToggle(row, on) {
        var tags = row.collection
            ? row.collection.tags.map(function (t) {
                return { id: t.id, name: t.name, colour: t.colour, local_only: t.local_only, tag_name: t.name };
            })
            : [{
                id: row.id,
                name: row.value,
                colour: row.style && row.style.colour ? row.style.colour : '#0088cc',
                local_only: !!row.local_only,
                tag_name: row.value
            }];
        tags.forEach(function (t) {
            if (on) {
                pick(t);
            } else {
                delete picked.global[t.tag_name];
                delete picked.local[t.tag_name];
            }
        });
        changed();
    }

    var host = root.querySelector('[data-browser-host]');
    loadIndexFilterBrowser(browserAssets).then(function () {
        if (!root.isConnected) { return; }
        host.innerHTML = '';
        browser = window.IndexFilterBrowser.mount(host, {
            kind: 'tag',
            scopes: browserCfg.scopes,
            source: browserCfg.source,
            tree: browserCfg.tree,
            label: browserCfg.label,
            strings: browserCfg.strings,
            collections: browserCfg.collections,
            open: browserCfg.open,
            selection: browserSelection(),
            onToggle: onToggle,
            reserve: 490
        });
        if (modalEl.classList.contains('show')) { browser.focus(); }
    }, function () {
        host.innerHTML = '<div class="text-center py-4 text-body-secondary small">'
            + '<i class="fas fa-triangle-exclamation me-2"></i></div>';
        host.firstChild.appendChild(document.createTextNode(labels.loadFailed));
    });
    modalEl.addEventListener('shown.bs.modal', function () {
        if (browser) { browser.focus(); }
    }, { once: true });
    modalEl.addEventListener('hidden.bs.modal', function () {
        if (browser) { browser.destroy(); }
    }, { once: true });

    renderSides();

    /*
     * A tag collection can carry galaxy clusters - they live in the collection as
     * `misp-galaxy:` tags - so a save here can change the galaxies card too.
     */
    function reloadGalaxiesCard() {
        var fn = window['reloadGalaxiesCard_' + uid.replace('-tags-', '-galaxies-')];
        if (typeof fn === 'function') { fn(); }
    }

    /*
     * After a successful save: prefer an event-view card reload hook
     * (window['<reloadHook>' + uid]); otherwise fall back to refreshing the
     * attribute index table (set by view_attributes.ctp).
     */
    function afterSave() {
        reloadGalaxiesCard();
        document.dispatchEvent(new CustomEvent('misp:tags-saved', { detail: { uid: uid } }));
        var cardReload = reloadHook ? window[reloadHook + uid] : null;
        if (typeof cardReload === 'function') { cardReload(); return; }

        /* No card hook (attribute context): the change shows in the index
           behind the modal. */
        reloadEventViewIndexTab();
    }

    function ids(side) {
        return entries(side).map(function (t) { return t.id; });
    }

    /* ─── Save ─── */
    var saveBtn = document.getElementById('edit-tags-save-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', function () {
            saveBtn.disabled = true;

            fetch(postUrl, {
                method:  'POST',
                headers: {
                    'Content-Type':     'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     getCsrfToken()
                },
                body: JSON.stringify({
                    global_ids: ids('global'),
                    local_ids:  ids('local')
                })
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.saved) {
                    var modal = document.getElementById('mainModal');
                    if (modal) {
                        (bootstrap.Modal.getInstance(modal)
                            || new bootstrap.Modal(modal)).hide();
                    }
                    showToast(data.success || <?= json_encode(__('Tags updated.')) ?>, 'success');
                    afterSave();
                } else {
                    showToast(data.errors || <?= json_encode(__('Failed to update tags.')) ?>, 'danger');
                    saveBtn.disabled = false;
                }
            })
            .catch(function () {
                showToast(<?= json_encode(__('Request failed — please try again.')) ?>, 'danger');
                saveBtn.disabled = false;
            });
        });
    }
</script>
