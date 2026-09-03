<?php
/*
 * Modal to pick global/local galaxy clusters for an object.
 *
 * Required params:
 *   $saveUrl               string  POST target (unescaped, h()'d here)
 *   $uid                   string  unique DOM/scope id (e.g. 'evt-galaxies-12')
 *   $galaxyList            [{id, name, icon}, ...]
 *   $currentGlobalClusters [{id, name, galaxy, hue}, ...]  pre-selected (global)
 *   $currentLocalClusters  [{id, name, galaxy, hue}, ...]  pre-selected (local)
 *   $mayModify             bool
 * Optional params:
 *   $headerEyebrow         string  small uppercase label (default "Galaxies")
 *   $reloadHook            string  window['<hook>' + uid] fn called after save;
 *                                  falls back to the attribute-index reload.
 */

$headerEyebrow = $headerEyebrow ?? __('Galaxies');
$reloadHook    = $reloadHook ?? '';

$postUrl   = h($saveUrl);
$searchUrl = h($baseurl . '/events/searchGalaxyClusters');

$initGJson = json_encode($currentGlobalClusters, JSON_HEX_TAG | JSON_HEX_AMP);
$initLJson = json_encode($currentLocalClusters,  JSON_HEX_TAG | JSON_HEX_AMP);

/* FontAwesome brand-icon names (rendered with the `fab` prefix) */
$brandIcons = [
    'github', 'gitlab', 'docker', 'linux', 'android', 'apple',
    'google', 'microsoft', 'facebook', 'twitter', 'linkedin',
    'btc', 'ethereum', 'optin-monster', 'internet-explorer',
];

/* Reusable section markup (category buttons + picker + selected area) */
$section = function ($scope, $iconClass, $title, $badgeHtml = '')
        use ($galaxyList, $brandIcons) {
    ob_start(); ?>
    <div class="w-100 px-2" data-section="<?= h($scope) ?>">
        <div class="d-flex align-items-center gap-2 fw-bold text-uppercase mb-2 text-galaxy"
             style="font-size:.65rem; letter-spacing:.1em;">
            <i class="<?= h($iconClass) ?>"></i>
            <?= h($title) ?>
            <?= $badgeHtml ?>
        </div>

        <!-- Category buttons: All + one per galaxy (scrollable) -->
        <div class="border rounded p-2 mb-2"
             style="max-height:118px; overflow-y:auto;">
            <div class="d-flex flex-wrap gap-2 galaxy-cat-list">
                <button type="button"
                        class="btn btn-sm btn-outline-galaxy galaxy-cat-btn active"
                        data-cat="all"><?= __('All Galaxies') ?></button>
                <?php foreach ($galaxyList as $g):
                    $pref = in_array($g['icon'], $brandIcons, true) ? 'fab' : 'fas';
                ?>
                    <button type="button"
                            class="btn btn-sm btn-outline-galaxy galaxy-cat-btn"
                            data-cat="galaxy"
                            data-galaxy-id="<?= (int)$g['id'] ?>"
                            title="<?= h($g['name']) ?>">
                        <i class="<?= $pref ?> fa-<?= h($g['icon']) ?> me-1"></i><?= h($g['name']) ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>

        <select class="galaxy-picker"
                placeholder="<?= __('Search clusters to add…') ?>"></select>
        <?= $this->element('genericElementsBS5/Forms/field_hint', [
            'text' => __('Type at least 2 characters to search across all galaxies.'),
        ]) ?>

        <div class="mt-2 d-flex flex-wrap gap-2 galaxy-selected"></div>
        <div class="text-muted small fst-italic galaxy-selected-empty">
            <?= __('No clusters selected.') ?>
        </div>
    </div>
    <?php return ob_get_clean();
};
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'galaxy',
    'eyebrow' => $headerEyebrow,
    'title' => __('Edit Galaxy Clusters'),
    'titleIcon' => 'fas fa-pen-to-square',
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <?= $section('global', 'fas fa-globe', __('Global Clusters')) ?>

        <?php
        $localBadge = '<span class="badge bg-warning text-dark fw-normal"'
            . ' style="font-size:.6rem; text-transform:none; letter-spacing:0;">'
            . h(__('Would not be synchronized with other instances'))
            . '</span>';
        echo $section('local', 'fas fa-user', __('Local Clusters'), $localBadge);
        ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'galaxy',
        'align' => 'end',
        'submit' => $mayModify ? [
            'label' => __('Save Clusters'),
            'icon' => 'fas fa-save',
            'id' => 'edit-galaxies-save-btn',
            'type' => 'button',
        ] : false,
    ]) ?>

</div>

<script>
    var postUrl    = <?= json_encode($postUrl) ?>;
    var searchUrl  = <?= json_encode($searchUrl) ?>;
    var uid        = <?= json_encode($uid) ?>;
    var reloadHook = <?= json_encode($reloadHook) ?>;
    var initSelected      = {
        global: <?= $initGJson ?: '[]' ?>,
        local:  <?= $initLJson ?: '[]' ?>
    };

    /*
     * One Global/Local section, driven by the shared picker in mispOvermind.js
     * (initGalaxyPickerSection): its own selection, badges and remote search
     * against the shared cluster endpoint.
     */
    function makeSection(scope) {
        return initGalaxyPickerSection(
            document.querySelector('[data-section="' + scope + '"]'),
            initSelected[scope],
            { searchUrl: searchUrl, localMarker: (scope === 'local') }
        );
    }

    var globalSection = makeSection('global');
    var localSection  = makeSection('local');

    /*
     * After a successful save: prefer an event-view card reload hook
     * (window['<reloadHook>' + uid]); otherwise fall back to refreshing the
     * attribute index table (set by view_attributes.ctp).
     */
    function afterSave() {
        var cardReload = reloadHook ? window[reloadHook + uid] : null;
        if (typeof cardReload === 'function') { cardReload(); return; }

        /*
         * No card hook (attribute context): reload whichever event-view index
         * tab is currently shown. Each tab exposes { loadFn, buildFn } on window
         * once rendered (view_attributes.ctp / Objects/index.ctp).
         */
        var tabs = [
            { sel: '.ajax-tab-content[data-url*="viewObjects"]',    api: window.mispView.objects },
            { sel: '.ajax-tab-content[data-url*="viewAttributes"]', api: window.mispView.attrs }
        ];
        function reload(api) {
            if (api && typeof api.loadFn === 'function'
                    && typeof api.buildFn === 'function') {
                api.loadFn(api.buildFn());
                return true;
            }
            return false;
        }
        /* Prefer the tab whose container is currently visible. */
        for (var i = 0; i < tabs.length; i++) {
            var cont = document.querySelector(tabs[i].sel);
            if (cont && cont.offsetParent !== null && reload(tabs[i].api)) { return; }
        }
        /* Fallback: any exposed tab API. */
        for (var j = 0; j < tabs.length; j++) {
            if (reload(tabs[j].api)) { return; }
        }
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
                    global_ids: globalSection.ids(),
                    local_ids:  localSection.ids()
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
