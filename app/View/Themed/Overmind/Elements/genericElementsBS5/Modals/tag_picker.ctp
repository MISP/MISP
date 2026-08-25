<?php
/*
 * Modal to pick global/local tags for an object.
 *
 * Required params:
 *   $saveUrl           string  POST target (unescaped, h()'d here)
 *   $uid               string  unique DOM/scope id (e.g. 'evt-tags-12')
 *   $allTags           [{id, name, colour}, ...]
 *   $customTags        [{id, name, colour}, ...]
 *   $tagCollections    [{id, name, tags:[{id,name,colour}]}, ...]
 *   $currentGlobalTags [{id, name, colour}, ...]   pre-selected (global)
 *   $currentLocalTags  [{id, name, colour}, ...]   pre-selected (local)
 *   $mayModify         bool
 * Optional params:
 *   $headerEyebrow     string  small uppercase label (default "Tags")
 *   $reloadHook        string  window['<hook>' + uid] fn called after save;
 *                              falls back to the attribute-index reload.
 */

$headerEyebrow = $headerEyebrow ?? __('Tags');
$reloadHook    = $reloadHook ?? '';

$postUrl   = h($saveUrl);

$allJson    = json_encode($allTags,           JSON_HEX_TAG | JSON_HEX_AMP);
$customJson = json_encode($customTags,        JSON_HEX_TAG | JSON_HEX_AMP);
$collJson   = json_encode($tagCollections,    JSON_HEX_TAG | JSON_HEX_AMP);
$initGJson  = json_encode($currentGlobalTags, JSON_HEX_TAG | JSON_HEX_AMP);
$initLJson  = json_encode($currentLocalTags,  JSON_HEX_TAG | JSON_HEX_AMP);

/* Reusable section markup (category buttons + picker + selected area) */
$section = function ($scope, $iconClass, $title, $badgeHtml = '') {
    ob_start(); ?>
    <div class="w-100 px-2" data-section="<?= h($scope) ?>">
        <div class="d-flex align-items-center gap-2 fw-bold text-uppercase mb-2 text-tag"
             style="font-size:.65rem; letter-spacing:.1em;">
            <i class="<?= h($iconClass) ?>"></i>
            <?= h($title) ?>
            <?= $badgeHtml ?>
        </div>

        <!-- Category buttons -->
        <div class="d-flex flex-wrap gap-2 mb-2 tag-cat-list">
            <button type="button" class="btn btn-sm btn-outline-tag tag-cat-btn active"
                    data-cat="all"><?= __('All Tags') ?></button>
            <button type="button" class="btn btn-sm btn-outline-tag tag-cat-btn"
                    data-cat="custom"><?= __('Custom Tags') ?></button>
            <button type="button" class="btn btn-sm btn-outline-tag tag-cat-btn"
                    data-cat="collections"><?= __('Tag Collections') ?></button>
        </div>

        <select class="tag-picker"
                placeholder="<?= __('Search tags to add…') ?>"></select>

        <div class="mt-2 d-flex flex-wrap tag-selected"></div>
        <div class="text-muted small fst-italic tag-selected-empty">
            <?= __('No tags selected.') ?>
        </div>
    </div>
    <?php return ob_get_clean();
};
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(219,106,71,.06);
            border-bottom:2px solid var(--tag);">
    <div>
        <div class="text-uppercase fw-semibold mb-1 text-tag"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= h($headerEyebrow) ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <span class="fas fa-pen-to-square text-tag"
                  style="font-size:1.25rem;"></span>
            <?= __('Edit Tags') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Pick a category, search the input, and the selected tags appear below.') ?>
        </p>
    </div>
    <span class="misp-icon misp-icon-tag misp-simple text-tag"
          style="font-size:2rem; opacity:.5;"></span>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <?= $section('global', 'fas fa-globe', __('Global Tags')) ?>

        <?php
        $localBadge = '<span class="badge bg-warning text-dark fw-normal"'
            . ' style="font-size:.6rem; text-transform:none; letter-spacing:0;">'
            . h(__('Would not be synchronized with other instances'))
            . '</span>';
        echo $section('local', 'fas fa-user', __('Local Tags'), $localBadge);
        ?>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-end align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <button type="button" class="btn btn-outline-secondary btn-sm"
                data-bs-dismiss="modal">
            <i class="fas fa-times me-1"></i><?= __('Discard') ?>
        </button>
        <?php if ($mayModify): ?>
        <button type="button"
                id="edit-tags-save-btn"
                class="btn btn-tag btn-sm text-white">
            <i class="fas fa-save me-1"></i>
            <?= __('Save Tags') ?>
        </button>
        <?php endif; ?>
    </div>

</div>

<script>
    var postUrl    = <?= json_encode($postUrl) ?>;
    var uid        = <?= json_encode($uid) ?>;
    var reloadHook = <?= json_encode($reloadHook) ?>;
    var catData    = {
        all:         <?= $allJson    ?: '[]' ?>,
        custom:      <?= $customJson ?: '[]' ?>,
        collections: <?= $collJson   ?: '[]' ?>
    };
    var initSelected = {
        global: <?= $initGJson ?: '[]' ?>,
        local:  <?= $initLJson ?: '[]' ?>
    };

    /*
     * One section per locality. initTagPickerSection() (mispOvermind.js) is the
     * picker itself — the same code the in-form field uses, so both look and
     * behave identically.
     */
    function makeSection(scope, initTags) {
        return initTagPickerSection(
            document.querySelector('[data-section="' + scope + '"]'),
            catData,
            initTags,
            { localMarker: scope === 'local' }
        );
    }

    var globalSection = makeSection('global', initSelected.global);
    var localSection  = makeSection('local',  initSelected.local);

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
