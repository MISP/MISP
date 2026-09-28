<?php
App::uses('CakeNumber', 'Utility');
$scope = $lookupStatus['scope'] ?? [];
$progress = $lookupStatus['progress'] ?? [];
$statistics = $lookupStatus['statistics'] ?? [];
$bytes = function ($value) {
    return $value === null ? __('Unavailable') : CakeNumber::toReadableSize($value);
};
?>
<?= $this->Html->css('fast-lookup') ?>
<div class="servers index fast-lookup-index">
    <h2><?= __('Fast lookup index') ?></h2>
    <?php if (!$lookupEnabled): ?>
        <div class="alert"><?= __('The lookup API is disabled. Enable MISP.fast_lookup_enabled in Server Settings after preparing the index.') ?></div>
    <?php endif; ?>
    <div id="fast-lookup-status" role="status" aria-live="polite">
        <p><strong><?= __('Status') ?>:</strong> <span data-lookup-status><?= h($lookupStatus['status']) ?></span></p>
        <p data-lookup-message><?= h($lookupStatus['message'] ?? '') ?></p>
        <p><span data-lookup-processed><?= h($progress['processed_attributes'] ?? 0) ?></span> <?= __('attributes out of') ?>
            <span data-lookup-total><?= h($progress['total_attributes'] ?? 0) ?></span> <?= __('attributes processed') ?>.
            <?= __('Estimated time remaining') ?>: <span data-lookup-eta><?= isset($progress['eta_seconds']) ? h($progress['eta_seconds']) . ' ' . __('seconds') : __('Calculating') ?></span></p>
        <progress data-lookup-progress max="100" value="<?= h($progress['percent'] ?? 0) ?>" aria-label="<?= __('Backfill completion') ?>"></progress>
        <p><?= __('Lookup requests return no results until the first complete build. Later rebuilds run beside the current index, which keeps answering until the new one replaces it.') ?></p>
        <?php if (!empty($lookupStatus['build'])): ?>
            <p><strong><?= __('Rebuild in progress') ?>:</strong> <?= h($lookupStatus['build']['progress']['percent']) ?>%
            <?php if (!empty($lookupStatus['build']['error'])): ?><span class="alert"><?= h($lookupStatus['build']['error']) ?></span><?php endif; ?></p>
        <?php endif; ?>
    </div>
    <h3><?= __('Scope') ?></h3>
    <dl class="lookup-scope">
        <dt><?= __('Events') ?></dt><dd><?= isset($scope['published_only']) ? ($scope['published_only'] ? __('Published events only') : __('Published and unpublished events')) : __('Invalid configuration') ?></dd>
        <dt><?= __('Attribute types') ?></dt><dd><?= h(isset($scope['attribute_types']) ? implode(', ', $scope['attribute_types']) : __('Invalid configuration')) ?></dd>
        <dt><?= __('Maximum values per request') ?></dt><dd><?= h($scope['max_values'] ?? __('Invalid configuration')) ?></dd>
        <dt><?= __('Matching') ?></dt><dd><?= __('Exact IOC values, containing IPv4/IPv6 ranges, and parent domains. Caller permissions are checked for every response.') ?></dd>
    </dl>
    <p><?= __('Change the scope and request limit under MISP.fast_lookup_* in Server Settings. Scope changes require rebuilding the index.') ?></p>
    <h3><?= __('Backfill') ?></h3>
    <?php if (isset($scope['configuration_valid']) && !$scope['configuration_valid']): ?>
        <p class="alert"><?= __('Correct the fast lookup configuration in Server Settings before starting a backfill.') ?></p>
    <?php elseif ($backgroundJobs): ?>
        <p><?= __('Rebuild scans existing events from the beginning. Resume continues an interrupted backfill or pending event updates.') ?></p>
        <?= $this->Form->create('Server', ['url' => ['action' => 'rebuildFastLookup']]) ?>
        <?= $this->Form->input('mode', ['type' => 'select', 'label' => __('Operation'), 'options' => ['rebuild' => __('Rebuild index'), 'resume' => __('Resume backfill')]]) ?>
        <?= $this->Form->end(['label' => __('Start backfill'), 'class' => 'btn btn-primary']) ?>
    <?php else: ?>
        <p><?= __('Background jobs are disabled. Run one of these commands as the MISP service user:') ?></p>
        <pre>app/Console/cake Admin rebuildFastLookup
app/Console/cake Admin resumeFastLookup
app/Console/cake Admin processFastLookup</pre>
        <p><?= __('Schedule processFastLookup regularly to drain updates after large imports or outages.') ?></p>
    <?php endif; ?>
    <h3><?= __('Filter and memory') ?></h3>
    <p><?= __('The Bloom filter holds every indexed value as a token and only proves absence; values it cannot rule out are checked in SQL. IP ranges and domains also keep attribute lists. Edits and deletions leave stale tokens until the next rebuild; SQL removes them from results.') ?></p>
    <p><?= __('Measured at') ?>: <?= h($statistics['measured_at'] ?? __('Not yet measured')) ?>.
        <a class="btn" href="<?= h($baseurl) ?>/servers/fastLookup?metrics=1"><?= __('Measure memory statistics') ?></a></p>
    <?php if (!empty($statistics['memory_unavailable_reason'])): ?>
        <p class="alert"><?= h($statistics['memory_unavailable_reason']) ?></p>
    <?php endif; ?>
    <?php if ($statistics && isset($statistics['inserted'], $statistics['capacity']) && $statistics['inserted'] > $statistics['capacity']): ?>
        <p class="alert"><?= __('The filter holds more entries than its configured capacity. Answers stay correct, but lookups are slower; schedule a rebuild.') ?></p>
    <?php endif; ?>
    <?php if ($statistics): ?>
        <dl class="lookup-scope">
            <dt><?= __('Tokens in the filter') ?></dt><dd><?= h(number_format($statistics['inserted'])) ?> / <?= h(number_format($statistics['capacity'])) ?></dd>
            <dt><?= __('Stale entries (upper bound)') ?></dt><dd><?= h(number_format($statistics['stale'])) ?></dd>
            <dt><?= __('False-positive rate') ?></dt><dd><?= h(sprintf('%.4f%%', 100 * $statistics['estimated_false_positive_rate'])) ?> (<?= __('configured') ?> <?= h(sprintf('%.4f%%', 100 * $statistics['rate'])) ?>)</dd>
            <dt><?= __('Bloom filter memory') ?></dt><dd><?= h($bytes($statistics['filter_bytes'])) ?></dd>
            <dt><?= __('Range and domain lists') ?></dt><dd><?= h($bytes($statistics['posting_bytes'])) ?> (<?= h(number_format($statistics['posting_entries'])) ?> <?= __('entries') ?>)</dd>
            <dt><?= __('Shared index metadata') ?></dt><dd><?= h($bytes($statistics['shared_memory_bytes'])) ?></dd>
        </dl>
    <?php else: ?>
        <p><?= __('Statistics are unavailable until an index generation exists.') ?></p>
    <?php endif; ?>
    <p class="muted" id="fast-lookup-poll-state"><?= __('Progress refreshes every five seconds. Memory statistics refresh only when requested.') ?></p>
</div>
<?= $this->element('/genericElements/SideMenu/side_menu', ['menuList' => 'admin', 'menuItem' => 'fastLookup']) ?>
<script>
(function () {
    'use strict';
    var url = <?= json_encode($baseurl . '/servers/fastLookup', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var timer;
    function text(selector, value) { document.querySelector(selector).textContent = value; }
    function poll() {
        if (document.hidden) { timer = setTimeout(poll, 5000); return; }
        $.ajax({url: url, dataType: 'json', cache: false, headers: {'Accept': 'application/json'}}).done(function (data) {
            var progress = data.progress || {};
            text('[data-lookup-status]', data.status);
            text('[data-lookup-message]', data.message || '');
            text('[data-lookup-processed]', progress.processed_attributes || 0);
            text('[data-lookup-total]', progress.total_attributes || 0);
            text('[data-lookup-eta]', progress.eta_seconds == null ? <?= json_encode(__('Calculating')) ?> : progress.eta_seconds + ' ' + <?= json_encode(__('seconds')) ?>);
            document.querySelector('[data-lookup-progress]').value = progress.percent || 0;
            text('#fast-lookup-poll-state', <?= json_encode(__('Progress refreshed. Memory statistics refresh only when requested.')) ?>);
        }).fail(function () {
            text('#fast-lookup-poll-state', <?= json_encode(__('Progress could not be refreshed. Displayed values may be out of date.')) ?>);
        }).always(function () { timer = setTimeout(poll, 5000); });
    }
    timer = setTimeout(poll, 5000);
    window.addEventListener('pagehide', function () { clearTimeout(timer); });
}());
</script>
