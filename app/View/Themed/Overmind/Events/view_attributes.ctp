<?php
$namedParams     = $this->request->params['named'] ?? [];
$attrEventId     = $event['Event']['id'];
$currentDeleted  = (int)($namedParams['deleted']  ?? 0);
$currentProposal = (int)($namedParams['proposal'] ?? 0);
$currentCategory = $namedParams['category'] ?? '';
$currentType     = $namedParams['type']     ?? '';
$currentWarninglist = $namedParams['warninglist'] ?? '';

$paginatorUrl = [
    'controller' => 'events',
    'action'     => 'viewAttributes',
    $attrEventId,
];
if (!empty($extended)) {
    $paginatorUrl['extended'] = 1;
}
if (!empty($extending)) {
    $paginatorUrl['extending'] = 1;
}
/*
 * Restore named filters to the paginator's base URL to maintain state across pages.
 */
foreach (($this->request->params['named'] ?? []) as $namedKey => $namedValue) {
    if ($namedKey !== 'page') {
        $paginatorUrl[$namedKey] = $namedValue;
    }
}
$this->Paginator->options(['url' => $paginatorUrl]);

?>

<?php if (!empty($warninglistFilter)): ?>
<div class="alert alert-warning d-flex align-items-center gap-2 py-2 px-3 mb-3"
     id="attr-wl-filter">
    <i class="fas fa-exclamation-triangle"></i>
    <span class="small">
        <?= __('Only the attributes flagged by the warning list') ?>
        <strong><?= h($warninglistFilter['name']) ?></strong>
    </span>
    <a href="<?= h($baseurl . '/warninglists/view/'
        . (int)$warninglistFilter['id']) ?>"
       class="btn btn-sm btn-outline-secondary ms-auto">
        <i class="fas fa-external-link-alt me-1"></i><?= __('Open list') ?>
    </a>
    <button type="button" class="btn btn-sm btn-outline-danger"
            id="attr-wl-filter-clear">
        <i class="fas fa-times me-1"></i><?= __('Clear') ?>
    </button>
</div>
<?php endif; ?>

<?php
echo $this->element('Attributes/index', [
    'attributes'    => $attributes,
    'show_event_id' => false,
]);
?>

<script>
(function () {
    var _sel     = '.ajax-tab-content[data-url*="viewAttributes"]';
    var _msgFail = <?= json_encode(__('Could not load attributes.')) ?>;

    // Shared mutable state — updated every IIFE run so ALL closures see latest values
    window.mispView = window.mispView || {};
    window.mispView.attrs = Object.assign(window.mispView.attrs || {}, {
        attrBase:      baseurl + '/events/viewAttributes/' + <?= json_encode(h($attrEventId)) ?>
                           + <?= json_encode($extensionSuffix ?? '') ?>,
        deletedState:  <?= (int)$currentDeleted ?>,
        proposalState: <?= (int)$currentProposal ?>,
        activeFilters: <?= json_encode(array_filter([
            'category'    => $currentCategory,
            'type'        => $currentType,
            'warninglist' => $currentWarninglist,
        ])) ?>,
    });

    function getContainer() {
        return document.querySelector(_sel);
    }

    /*
     * This tab's own URL shape: `events/viewAttributes/<id>` plus named
     * segments, not the `/attributes/index/...` the shared bar would build.
     * The column filters are read straight off the bar's controls — the draft
     * in `filter_bar.ctp` owns them, and reading a private copy of their
     * values is how this tab used to drift out of sync with what was on
     * screen. `warninglist` has no control (it arrives from the banner), so
     * it stays in the state object.
     */
    function buildBaseUrl() {
        var S   = window.mispView.attrs;
        var url = S.attrBase;
        if (S.deletedState) url += '/deleted:' + S.deletedState;
        if (S.proposalState) url += '/proposal:' + S.proposalState;
        if (S.activeFilters.warninglist) {
            url += '/warninglist:' + encodeURIComponent(S.activeFilters.warninglist);
        }
        return url;
    }

    // Full URL: the base plus whatever the filter bar's controls hold.
    function buildAttrsUrl() {
        var url  = buildBaseUrl();
        var cont = getContainer();
        if (!cont) { return url; }
        cont.querySelectorAll('select.filter-draft-input').forEach(function (sel) {
            var name  = sel.getAttribute('name');
            var value = (sel.value || '').trim();
            if (name && value !== '') { url += '/' + name + ':' + encodeURIComponent(value); }
        });
        var field = cont.querySelector('#filterField');
        if (field && field.value.trim()) { url += '/searchFor:' + encodeURIComponent(field.value.trim()); }
        return url;
    }

    function loadAttributes(url) {
        var container = getContainer();
        if (!container) return;
        // Keep the container's own URL in sync: filter_bar rebuilds pagination
        // and "Clear all" from it, and it must not resurrect a filter we just dropped
        container.dataset.url = url;
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.text(); })
            .then(function (html) {
                container.innerHTML = html;
                container.querySelectorAll('script').forEach(function (old) {
                    var s = document.createElement('script');
                    if (old.src) { s.src = old.src; } else { s.textContent = old.textContent; }
                    document.head.appendChild(s); document.head.removeChild(s);
                });
                // The bar renders the term back into #filterField itself, and
                // it has to be there *before* the draft reads its state — a
                // value poked in afterwards leaves the summary saying there is
                // no filter over a box that holds one.
                registerFilterOverride(container);
            })
            .catch(function () { showMessage('fail', _msgFail); });
    }

    /*
     * The filter bar wires itself (initScaffoldFilterDraft), so all this tab
     * has to say is "the URLs are mine". Handing over the two functions beats
     * what used to be here: a second TomSelect over every control, a private
     * copy of their values, and a change listener that ran a query per
     * keystroke-and-blur — the very thing the draft exists to stop.
     */
    function registerFilterOverride(container) {
        if (!container) { return; }
        container.__indexFilterOverride = {
            buildUrl: buildAttrsUrl,
            reload: function (url) { loadAttributes(url); return true; },
        };
    }

    // Expose latest function refs so OLD closures (e.g. pagination) can call current impls
    window.mispView.attrs.buildFn = buildAttrsUrl;
    window.mispView.attrs.loadFn  = loadAttributes;

    var container = getContainer();

    // Pagination — delegated on the container, registered only once across reloads
    if (container && !container.__attrPaginationReady) {
        container.__attrPaginationReady = true;
        container.addEventListener('click', function (e) {
            if (e.defaultPrevented) return;
            var link = e.target.closest('.pagination a');
            if (!link) return;
            e.preventDefault();
            var m    = (link.getAttribute('href') || '').match(/page[:\-](\d+)/);
            var page = m ? m[1] : '1';
            window.mispView.attrs.loadFn(
                window.mispView.attrs.buildFn() + '/page:' + page
            );
        });
    }

    function wireToggle(selector, stateKey, onValue) {
        var btn = container ? container.querySelector(selector) : null;
        if (!btn) return;
        var fresh = btn.cloneNode(true);
        btn.parentNode.replaceChild(fresh, btn);
        fresh.addEventListener('click', function (e) {
            e.preventDefault();
            var S = window.mispView.attrs;
            S[stateKey] = S[stateKey] ? 0 : onValue;
            loadAttributes(buildAttrsUrl());
        });
    }
    wireToggle('.attr-deleted-toggle', 'deletedState', 2);
    wireToggle('.attr-proposal-toggle', 'proposalState', 1);

    // Warning-list banner: drop the filter and re-render the full list.
    var wlClear = container
        ? container.querySelector('#attr-wl-filter-clear')
        : null;
    if (wlClear) {
        wlClear.addEventListener('click', function () {
            delete window.mispView.attrs.activeFilters.warninglist;
            loadAttributes(buildAttrsUrl());
        });
    }

    registerFilterOverride(container);
}());
</script>
