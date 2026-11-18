<div class="events index">
    <h2><?= __('Generate MISP feed') ?></h2>
    <p id="feed-export-state"><?= __('Waiting for the background worker…') ?></p>
    <progress id="feed-export-progress" max="100" value="0"></progress>
    <p><a id="feed-export-download" class="btn btn-primary hidden" href="<?= $baseurl ?>/events/downloadModuleExport/<?= h($jobId) ?>"><?= __('Download feed ZIP') ?></a></p>
</div>
<script>
(function pollFeedExport() {
    $.getJSON(baseurl + '/events/moduleExportStatus/' + <?= json_encode((string)$jobId) ?>)
        .done(function (job) {
            $('#feed-export-state').text(job.status + ': ' + job.done + ' / ' + job.total + ' events; ' + job.events + ' exported' + (job.message ? '. ' + job.message : ''));
            $('#feed-export-progress').val(job.status === 'ready' ? 100 : Math.floor(95 * job.done / Math.max(1, job.total)));
            if (job.status === 'ready') {
                $('#feed-export-download').removeClass('hidden');
            } else if (job.status === 'queued' || job.status === 'running') {
                setTimeout(pollFeedExport, 2000);
            }
        }).fail(function () {
            $('#feed-export-state').text(<?= json_encode(__('Could not read job status. Reload this page to retry.')) ?>);
        });
})();
</script>
