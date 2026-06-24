<?php
$this->Paginator->options([
    'url' => [
        'controller' => 'events',
        'action'     => 'viewEventReports',
        $event['Event']['id'],
    ]
]);
?>

<?php echo $this->element('EventReports/index', [
    'reports' => $reports,
]); ?>

<script>
(function () {
    var eventId      = '<?= h($event['Event']['id']) ?>';
    var _sel         = '.ajax-tab-content[data-url*="viewEventReports"]';
    var _msgFail     = <?= json_encode(__('Could not load event reports.')) ?>;
    var _labelActive = <?= json_encode(__('Active filters')) ?>;
    var _labelClear  = <?= json_encode(__('Clear')) ?>;

    function getContainer() {
        return document.querySelector(_sel);
    }

    function loadEventReports(url, searchTerm) {
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
                    if (old.src) { s.src = old.src; }
                    else { s.textContent = old.textContent; }
                    document.head.appendChild(s);
                    document.head.removeChild(s);
                });
                // After scripts ran → #filterField has been cloned → restore value
                var field = container.querySelector('#filterField');
                if (field && searchTerm) field.value = searchTerm;
                updateActiveFilterBadge(
                    container,
                    searchTerm,
                    function () {
                        loadEventReports(
                            baseurl + '/events/viewEventReports/' + eventId,
                            ''
                        );
                    },
                    _labelActive,
                    _labelClear
                );
            })
            .catch(function () {
                showMessage('fail', _msgFail);
            });
    }

    function buildReportsUrl() {
        var field = document.querySelector(_sel + ' #filterField');
        var value = field ? field.value.trim() : '';
        var url   = baseurl + '/events/viewEventReports/' + eventId;
        if (value) url += '/searchFor:' + encodeURIComponent(value);
        return url;
    }

    // Clone #filterButton and #filterField to strip filter_bar.ctp's
    // window.location.href listeners (click on button + keypress Enter on field).
    var filterBtn = document.querySelector(_sel + ' #filterButton');
    if (filterBtn) {
        var newBtn = filterBtn.cloneNode(true);
        filterBtn.parentNode.replaceChild(newBtn, filterBtn);
        newBtn.addEventListener('click', function () {
            loadEventReports(buildReportsUrl());
        });
    }

    var filterField = document.querySelector(_sel + ' #filterField');
    if (filterField) {
        var newField = filterField.cloneNode(true);
        filterField.parentNode.replaceChild(newField, filterField);
        newField.addEventListener('keypress', function (e) {
            if (e.key !== 'Enter') return;
            e.preventDefault();
            loadEventReports(buildReportsUrl());
        });
    }

    // Pagination scoped to container only.
    var container = getContainer();
    if (container) {
        container.addEventListener('click', function (e) {
            var link = e.target.closest('.pagination a');
            if (!link) return;
            e.preventDefault();
            var href  = link.getAttribute('href');
            var match = href.match(/page[:\-](\d+)/);
            var page  = match ? match[1] : '1';
            loadEventReports(
                baseurl + '/events/viewEventReports/' + eventId + '/page:' + page
            );
        });
    }
}());
</script>
