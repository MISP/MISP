<?php
$this->Paginator->options([
    'url' => [
        'controller' => 'events',
        'action' => 'viewAttributes',
        $event['Event']['id']
    ]
]);

echo $this->element('Attributes/index', [
    'attributes' => $attributes,
    'show_event_id' => false,
]);
?>

<script>
(function() {
    var eventId = '<?= h($event['Event']['id']) ?>';

    // Intercept all pagination clicks and reload via AJAX instead
    document.addEventListener('click', function(e) {
        var link = e.target.closest('.pagination a');
        if (!link) return;
        e.preventDefault();

        var href = link.getAttribute('href');
        var match = href.match(/page[:\-](\d+)/);
        if (!match) return;
        var page = match[1];

        var url = baseurl + '/events/viewAttributes/' + eventId + '/page:' + page;

        fetch(url)
            .then(function(response) { return response.text(); })
            .then(function(data) {
                var container = document.querySelector('.ajax-tab-content[data-url*="viewAttributes"]');
                if (container) {
                    container.innerHTML = data;
                    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            })
            .catch(function() {
                showMessage('fail', 'Could not load attributes.');
            });
    });
})();
</script>
