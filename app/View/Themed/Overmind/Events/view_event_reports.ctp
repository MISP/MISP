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
    var eventId = '<?= h($event['Event']['id']) ?>';

    document.addEventListener('click', function (e) {
        var link = e.target.closest('.pagination a');
        if (!link) return;
        e.preventDefault();

        var href  = link.getAttribute('href');
        var match = href.match(/page[:\-](\d+)/);
        var page  = match ? match[1] : '1';

        var url = baseurl + '/events/viewEventReports/' + eventId
                + '/page:' + page;

        fetch(url)
            .then(function (r) { return r.text(); })
            .then(function (data) {
                var container = document.querySelector(
                    '.ajax-tab-content[data-url*="viewEventReports"]'
                );
                if (container) {
                    container.innerHTML = data;
                    container.scrollIntoView(
                        { behavior: 'smooth', block: 'start' }
                    );
                }
            })
            .catch(function () {
                showMessage('fail', '<?= __('Could not load event reports.') ?>');
            });
    });
}());
</script>
