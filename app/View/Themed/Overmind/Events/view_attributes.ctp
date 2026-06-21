<?php
$namedParams     = $this->request->params['named'] ?? [];
$attrEventId     = $event['Event']['id'];
$currentDeleted  = (int)($namedParams['deleted']  ?? 0);
$currentCategory = $namedParams['category'] ?? '';
$currentType     = $namedParams['type']     ?? '';

$this->Paginator->options([
    'url' => [
        'controller' => 'events',
        'action'     => 'viewAttributes',
        $attrEventId,
    ]
]);

echo $this->element('Attributes/index', [
    'attributes'    => $attributes,
    'show_event_id' => false,
]);
?>

<script>
(function () {
    var _sel     = '.ajax-tab-content[data-url*="viewAttributes"]';
    var _msgFail = <?= json_encode(__('Could not load attributes.')) ?>;
    var _lActive = <?= json_encode(__('Active filters')) ?>;
    var _lClear  = <?= json_encode(__('Clear')) ?>;

    // Shared mutable state — updated every IIFE run so ALL closures see latest values
    window.overmindAttrs = Object.assign(window.overmindAttrs || {}, {
        attrBase:      baseurl + '/events/viewAttributes/' + <?= json_encode(h($attrEventId)) ?>,
        deletedState:  <?= (int)$currentDeleted ?>,
        activeFilters: <?= json_encode(array_filter(['category' => $currentCategory, 'type' => $currentType])) ?>,
    });

    function getContainer() {
        return document.querySelector(_sel);
    }

    // URL without search term (deleted + column filters)
    function buildBaseUrl() {
        var S   = window.overmindAttrs;
        var url = S.attrBase;
        if (S.deletedState) url += '/deleted:' + S.deletedState;
        Object.keys(S.activeFilters).forEach(function (n) {
            if (S.activeFilters[n]) url += '/' + n + ':' + encodeURIComponent(S.activeFilters[n]);
        });
        return url;
    }

    // Full URL including current #filterField value
    function buildAttrsUrl() {
        var url   = buildBaseUrl();
        var cont  = getContainer();
        var field = cont ? cont.querySelector('#filterField') : null;
        if (field && field.value.trim()) url += '/searchFor:' + encodeURIComponent(field.value.trim());
        return url;
    }

    function loadAttributes(url, searchTerm) {
        if (searchTerm === undefined) {
            var m = url.match(/searchFor:([^/]+)/);
            searchTerm = m ? decodeURIComponent(m[1]) : '';
        }
        var container = getContainer();
        if (!container) return;
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.text(); })
            .then(function (html) {
                container.innerHTML = html;
                container.querySelectorAll('script').forEach(function (old) {
                    var s = document.createElement('script');
                    if (old.src) { s.src = old.src; } else { s.textContent = old.textContent; }
                    document.head.appendChild(s); document.head.removeChild(s);
                });
                var field = container.querySelector('#filterField');
                if (field && searchTerm) field.value = searchTerm;
                updateActiveFilterBadge(
                    container,
                    searchTerm,
                    function () { loadAttributes(buildBaseUrl(), ''); },
                    _lActive,
                    _lClear
                );
            })
            .catch(function () { showMessage('fail', _msgFail); });
    }

    function initMoreFilters(container) {
        container.querySelectorAll('.topbar-filter').forEach(function (sel) {
            var name = sel.getAttribute('name');
            if (!name) return;
            var newSel = sel.cloneNode(true);
            sel.parentNode.replaceChild(newSel, sel);
            // TomSelect for styling only — value changes come via native change event
            if (typeof TomSelect !== 'undefined') {
                new TomSelect(newSel, { allowEmptyOption: true, create: false });
                var currentVal = (window.overmindAttrs.activeFilters || {})[name];
                if (currentVal && newSel.tomselect) {
                    newSel.tomselect.setValue(currentVal, true);
                }
            }
            // Native change listener — fires after both plain-select and TomSelect changes
            newSel.addEventListener('change', function () {
                window.overmindAttrs.activeFilters[name] = newSel.value;
                loadAttributes(buildAttrsUrl());
            });
        });
    }

    // Expose latest function refs so OLD closures (e.g. pagination) can call current impls
    window.overmindAttrs.buildFn = buildAttrsUrl;
    window.overmindAttrs.loadFn  = loadAttributes;

    var container = getContainer();

    // Pagination — delegated on the container, registered only once across reloads
    if (container && !container.__attrPaginationReady) {
        container.__attrPaginationReady = true;
        container.addEventListener('click', function (e) {
            var link = e.target.closest('.pagination a');
            if (!link) return;
            e.preventDefault();
            var m    = (link.getAttribute('href') || '').match(/page[:\-](\d+)/);
            var page = m ? m[1] : '1';
            window.overmindAttrs.loadFn(
                window.overmindAttrs.buildFn() + '/page:' + page
            );
        });
    }

    // #filterButton — clone to strip filter_bar.ctp's navigation listener
    var filterBtn = container ? container.querySelector('#filterButton') : null;
    if (filterBtn) {
        var newBtn = filterBtn.cloneNode(true);
        filterBtn.parentNode.replaceChild(newBtn, filterBtn);
        newBtn.addEventListener('click', function () { loadAttributes(buildAttrsUrl()); });
    }

    // #filterField — clone, Enter triggers search
    var filterField = container ? container.querySelector('#filterField') : null;
    if (filterField) {
        var newField = filterField.cloneNode(true);
        filterField.parentNode.replaceChild(newField, filterField);
        newField.addEventListener('keypress', function (e) {
            if (e.key !== 'Enter') return;
            e.preventDefault();
            loadAttributes(buildAttrsUrl());
        });
    }

    // .attr-deleted-toggle — clone to override Attributes/index.ctp's capture listener
    var toggleBtn = container ? container.querySelector('.attr-deleted-toggle') : null;
    if (toggleBtn) {
        var newToggle = toggleBtn.cloneNode(true);
        toggleBtn.parentNode.replaceChild(newToggle, toggleBtn);
        newToggle.addEventListener('click', function (e) {
            e.preventDefault();
            var S          = window.overmindAttrs;
            var newDeleted = S.deletedState ? 0 : 1;
            var url        = S.attrBase;
            if (newDeleted) url += '/deleted:' + newDeleted;
            Object.keys(S.activeFilters).forEach(function (n) {
                if (S.activeFilters[n]) url += '/' + n + ':' + encodeURIComponent(S.activeFilters[n]);
            });
            var cont  = getContainer();
            var field = cont ? cont.querySelector('#filterField') : null;
            if (field && field.value.trim()) url += '/searchFor:' + encodeURIComponent(field.value.trim());
            loadAttributes(url);
        });
    }

    // TomSelect on More Filters dropdowns
    if (container) initMoreFilters(container);
}());
</script>
