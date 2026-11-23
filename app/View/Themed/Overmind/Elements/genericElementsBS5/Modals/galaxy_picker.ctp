<?php
/*
 * Modal to pick global/local galaxy clusters for an object.
 *
 * The clusters are picked in the column browser of the index filter bars
 * (index-filter-browser.js, mounted here): a pick is global, and its chip in
 * the lists below the browser moves it to the other side.
 *
 * Required params:
 *   $saveUrl               string  POST target (unescaped, h()'d here)
 *   $uid                   string  unique DOM/scope id (e.g. 'evt-galaxies-12')
 *   $currentGlobalClusters [{id, name, galaxy, hue, tag_name}, ...]  pre-selected (global)
 *   $currentLocalClusters  [{id, name, galaxy, hue, tag_name}, ...]  pre-selected (local)
 *   $mayModify             bool
 * Optional params:
 *   $headerEyebrow         string  small uppercase label (default "Galaxies")
 *   $title                 string  modal title (default "Edit Galaxy Clusters")
 *   $description           string  one line under the title
 *   $saveLabel             string  submit label (default "Save Clusters")
 *   $reloadHook            string  window['<hook>' + uid] fn called after save;
 *                                  falls back to the attribute-index reload.
 */
App::uses('IndexPicker', 'Tools');

$headerEyebrow = $headerEyebrow ?? __('Galaxies');
$reloadHook    = $reloadHook ?? '';

$postUrl   = h($saveUrl);

$initGJson = json_encode($currentGlobalClusters, JSON_HEX_TAG | JSON_HEX_AMP);
$initLJson = json_encode($currentLocalClusters,  JSON_HEX_TAG | JSON_HEX_AMP);

$browser = [
    'scopes'  => $baseurl . '/galaxies/pickerScopes',
    'source'  => $baseurl . '/galaxy_clusters/pickerSearch',
    'label'   => __('Galaxy clusters'),
    'strings' => IndexPicker::browserStrings(),
];

$sideHead = 'd-flex align-items-center gap-2 fw-bold text-uppercase mb-2 text-galaxy';
$sideHeadStyle = 'font-size:.65rem; letter-spacing:.1em;';
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'galaxy',
    'eyebrow' => $headerEyebrow,
    'title' => $title ?? __('Edit Galaxy Clusters'),
    'titleIcon' => 'fas fa-pen-to-square',
    'description' => $description ?? '',
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
]) ?>

<div class="container-fluid px-4 py-4" id="<?= h($uid) ?>-picker">

    <div class="d-flex flex-column gap-3">

        <div class="ifb-accented" style="--ifb-accent: var(--bs-galaxy);" data-browser-host>
            <div class="text-center py-5 text-body-secondary">
                <div class="misp-loader misp-loader-sm" role="status"></div>
            </div>
        </div>

        <div class="d-flex flex-column gap-3">
            <div data-side="global">
                <div class="<?= $sideHead ?>" style="<?= $sideHeadStyle ?>">
                    <i class="fas fa-globe"></i>
                    <?= __('Global Clusters') ?>
                    <span class="fw-normal text-body-secondary" data-side-count></span>
                </div>
                <div class="d-flex flex-wrap gap-2" data-side-list></div>
                <div class="text-muted small fst-italic" data-side-empty><?= __('No clusters selected.') ?></div>
            </div>
            <div data-side="local">
                <div class="<?= $sideHead ?>" style="<?= $sideHeadStyle ?>">
                    <i class="fas fa-user"></i>
                    <?= __('Local Clusters') ?>
                    <span class="fw-normal text-body-secondary" data-side-count></span>
                    <span class="badge bg-warning text-dark fw-normal" style="font-size:.6rem; text-transform:none; letter-spacing:0;">
                        <?= __('Would not be synchronized with other instances') ?>
                    </span>
                </div>
                <div class="d-flex flex-wrap gap-2" data-side-list></div>
                <div class="text-muted small fst-italic" data-side-empty><?= __('No clusters selected.') ?></div>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'galaxy',
        'align' => 'end',
        'submit' => $mayModify ? [
            'label' => $saveLabel ?? __('Save Clusters'),
            'icon' => 'fas fa-save',
            'id' => 'edit-galaxies-save-btn',
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
        'remove' => __('Remove'),
        'showWhere' => __('Show where it lives'),
        'loadFailed' => __('The cluster browser could not be loaded.'),
    ], JSON_HEX_TAG | JSON_HEX_AMP) ?>;

    /* Tag name => {id, name, galaxy, hue, tag_name}, per side. A mass edit can carry one cluster on both. */
    var picked = { global: {}, local: {} };
    [['global', <?= $initGJson ?: '[]' ?>], ['local', <?= $initLJson ?: '[]' ?>]].forEach(function (side) {
        side[1].forEach(function (c) { picked[side[0]][c.tag_name] = c; });
    });
    var browser = null;

    function noLink() {
        return null;
    }

    function entries(side) {
        return Object.keys(picked[side]).map(function (tag) { return picked[side][tag]; });
    }

    /* What the browser ticks: a cluster on both sides shows as global. */
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
            list.forEach(function (c) { byId[c.id] = c; });
            box.querySelector('[data-side-count]').textContent = list.length ? '(' + list.length + ')' : '';
            box.querySelector('[data-side-empty]').classList.toggle('d-none', list.length > 0);
            var el = box.querySelector('[data-side-list]');
            el.innerHTML = TagChips.clusters(list.map(function (c) {
                return { id: c.id, value: c.name, galaxy: c.galaxy, hue: c.hue, local: side === 'local' };
            }), { href: noLink });
            el.querySelectorAll('.hg-unit[data-cluster-id]').forEach(function (unit) {
                var c = byId[unit.getAttribute('data-cluster-id')];
                if (!c) { return; }
                unit.title = labels.showWhere;
                unit.style.cursor = 'pointer';
                unit.addEventListener('click', function () {
                    if (browser) { browser.reveal(c.tag_name); }
                });
                unit.appendChild(chipButton(
                    '<i class="fas ' + (side === 'global' ? 'fa-user' : 'fa-globe') + '"></i>',
                    side === 'global' ? labels.makeLocal : labels.makeGlobal,
                    function () {
                        delete picked[side][c.tag_name];
                        if (!picked[other][c.tag_name]) { picked[other][c.tag_name] = c; }
                        changed();
                    }
                ));
                unit.appendChild(chipButton('&times;', labels.remove, function () {
                    delete picked[side][c.tag_name];
                    changed();
                }));
            });
        });
    }

    function changed() {
        renderSides();
        if (browser) { browser.select(browserSelection()); }
    }

    function onToggle(row, on) {
        if (on) {
            picked.global[row.value] = {
                id: row.id,
                name: row.label,
                galaxy: row.style && row.style.galaxy ? row.style.galaxy : '',
                tag_name: row.value
            };
        } else {
            delete picked.global[row.value];
            delete picked.local[row.value];
        }
        changed();
    }

    var host = root.querySelector('[data-browser-host]');
    loadIndexFilterBrowser(browserAssets).then(function () {
        if (!root.isConnected) { return; }
        host.innerHTML = '';
        browser = window.IndexFilterBrowser.mount(host, {
            kind: 'galaxy',
            scopes: browserCfg.scopes,
            source: browserCfg.source,
            label: browserCfg.label,
            strings: browserCfg.strings,
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
     * After a successful save: prefer an event-view card reload hook
     * (window['<reloadHook>' + uid]); otherwise fall back to refreshing the
     * attribute index table (set by view_attributes.ctp).
     */
    function afterSave() {
        var cardReload = reloadHook ? window[reloadHook + uid] : null;
        if (typeof cardReload === 'function') { cardReload(); return; }

        /* No card hook (attribute context): the change shows in the index
           behind the modal. */
        reloadEventViewIndexTab();
    }

    function ids(side) {
        return entries(side).map(function (c) { return c.id; });
    }

    /* ─── Save ─── */
    var saveBtn = document.getElementById('edit-galaxies-save-btn');
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
                    showToast(data.success || <?= json_encode(__('Galaxy clusters updated.')) ?>, 'success');
                    afterSave();
                } else {
                    showToast(data.errors || <?= json_encode(__('Failed to update clusters.')) ?>, 'danger');
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
