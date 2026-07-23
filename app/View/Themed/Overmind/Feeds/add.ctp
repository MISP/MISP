<?php
// Overmind BS5 add/edit form for a Feed. Rendered layout-less as a modal
// fragment (opened via openModal). Self-contained: under Overmind only
// mispOvermind.js is loaded, so the legacy misp.js helpers (feedFormUpdate /
// checkSharingGroup / add_basic_auth) are re-implemented inline below.
//
// The pull filter-rules are edited as a JSON blob (with a read-only summary of
// the current rules) rather than the legacy visual rule-builder — that builder
// is a heavy shared widget tracked with the sync/feature pages in the parent
// plan. The JSON field keeps full capability parity (tags/orgs OR-NOT +
// url_params) and submits natively.
$edit = $this->request->params['action'] === 'edit';
$reqFeed = $this->request->data['Feed'] ?? [];
$entityFeed = $entity['Feed'] ?? [];

$distSelected = $reqFeed['distribution'] ?? 3;
$orgcSelected = $reqFeed['orgc_id'] ?? ($edit ? null : ($me['org_id'] ?? null));
$sgSelected = $reqFeed['sharing_group_id'] ?? null;
$tagSelected = $reqFeed['tag_id'] ?? '0';
$tagCollSelected = $reqFeed['tag_collection_id'] ?? '0';
$fixedSelected = $reqFeed['fixed_event'] ?? 0;
$sourceFormatSel = $reqFeed['source_format'] ?? 'freetext';
$inputSourceSel = $reqFeed['input_source'] ?? 'network';
$delimiterVal = $reqFeed['settings']['csv']['delimiter'] ?? ',';
$csvValueVal = $reqFeed['settings']['csv']['value'] ?? '';
$excludeRegexVal = $reqFeed['settings']['common']['excluderegex'] ?? '';

// Initial pull_rules JSON (pretty-printed) + a decoded summary.
if ($edit) {
    $rulesRaw = $reqFeed['pull_rules'] ?? ($entityFeed['rules'] ?? '');
} else {
    $rulesRaw = $defaultPullRules ?? '';
}
$rulesDecoded = !empty($rulesRaw) ? json_decode($rulesRaw, true) : null;
$rulesPretty = is_array($rulesDecoded)
    ? json_encode($rulesDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    : (string)$rulesRaw;

// Build the read-only rules summary (tags/orgs OR/NOT pills).
$ruleSummary = [];
if (is_array($rulesDecoded)) {
    $colours = ['OR' => 'text-bg-success', 'NOT' => 'text-bg-danger'];
    foreach (['tags', 'orgs'] as $scope) {
        if (empty($rulesDecoded[$scope])) {
            continue;
        }
        $pills = '';
        foreach (['OR', 'NOT'] as $bool) {
            if (empty($rulesDecoded[$scope][$bool])) {
                continue;
            }
            foreach ($rulesDecoded[$scope][$bool] as $val) {
                $pills .= sprintf('<span class="badge %s me-1">%s</span>', $colours[$bool], h($val));
            }
        }
        if ($pills !== '') {
            $ruleSummary[] = sprintf('<span class="fw-semibold me-1">%s:</span>%s', h(ucfirst($scope)), $pills);
        }
    }
}

$localFeedDisabled = !empty(Configure::read('Security.disable_local_feed_access'));

echo $this->Form->create('Feed', [
    'url' => $baseurl . '/feeds/' . ($edit ? 'edit/' . h($feedId ?? ($reqFeed['id'] ?? '')) : 'add'),
    'class' => 'feed-form',
]);
?>

<div class="card shadow-sm">
    <div class="card-body p-4">

        <h3 class="mb-3"><?= $edit ? __('Edit MISP feed') : __('Add MISP feed') ?></h3>
        <p class="text-muted"><?= __('Add a new feed source that can be pulled into this instance or cached for correlation.') ?></p>

        <?php if ($localFeedDisabled): ?>
            <div class="alert alert-warning">
                <?= __('Warning: local feeds are currently disabled by policy. To re-enable the feature, set the Security.disable_local_feed_access flag to false in the server settings (CLI only).') ?>
            </div>
        <?php endif; ?>

        <!-- ================= BASIC ================= -->
        <div class="fw-semibold mb-2"><?= __('Feed source') ?></div>
        <div class="row">
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('name', ['class' => 'form-control', 'placeholder' => __('Feed name'), 'required' => true]) ?>
            </div>
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('provider', __('Provider'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('provider', ['class' => 'form-control', 'placeholder' => __('Name of the content provider'), 'required' => true]) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-md-4 mb-3">
                <?= $this->Form->label('input_source', __('Input source'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('input_source', $dropdownData['inputSources'], [
                    'class' => 'form-select', 'id' => 'FeedInputSource', 'value' => $inputSourceSel, 'empty' => false,
                ]) ?>
            </div>
            <div class="col-md-4 mb-3">
                <?= $this->Form->label('source_format', __('Source format'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('source_format', $dropdownData['feedTypes'], [
                    'class' => 'form-select', 'id' => 'FeedSourceFormat', 'value' => $sourceFormatSel, 'empty' => false,
                ]) ?>
            </div>
            <div class="col-md-4 mb-3">
                <?= $this->Form->label('url', __('URL'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('url', ['class' => 'form-control', 'placeholder' => __('URL of the feed'), 'required' => true]) ?>
            </div>
        </div>

        <!-- HEADERS (network only) -->
        <div class="mb-3" id="HeadersDiv">
            <?= $this->Form->label('headers', __('Headers to pass with requests (e.g. Authorization)'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->textarea('headers', [
                'class' => 'form-control', 'id' => 'FeedHeaders', 'rows' => 3,
                'placeholder' => __('Line break separated list of headers in the "headername: value" format'),
            ]) ?>
            <div class="mt-2">
                <button type="button" class="btn btn-sm btn-outline-secondary" id="feedBasicAuthToggle"><?= __('Add basic auth') ?></button>
                <div id="feedBasicAuthForm" class="border rounded p-3 mt-2" style="display:none;">
                    <div class="row g-2">
                        <div class="col-md-5">
                            <input type="text" class="form-control form-control-sm" id="feedBasicAuthUser" placeholder="<?= __('Username') ?>">
                        </div>
                        <div class="col-md-5">
                            <input type="text" class="form-control form-control-sm" id="feedBasicAuthPass" placeholder="<?= __('Password') ?>">
                        </div>
                        <div class="col-md-2">
                            <button type="button" class="btn btn-sm btn-secondary w-100" id="feedBasicAuthAdd"><?= __('Add') ?></button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- DELETE LOCAL FILE (local only) -->
        <div class="form-check form-switch mb-3 optionalField" id="DeleteLocalFileDiv" style="display:none;">
            <?= $this->Form->checkbox('delete_local_file', ['class' => 'form-check-input', 'id' => 'FeedDeleteLocalFile']) ?>
            <?= $this->Form->label('FeedDeleteLocalFile', __('Delete local file after pulling'), ['class' => 'form-check-label']) ?>
        </div>

        <!-- ================= OPTIONS ================= -->
        <div class="fw-semibold mb-2 mt-2"><?= __('Options') ?></div>
        <div class="row">
            <div class="col-md-4">
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('enabled', ['class' => 'form-check-input', 'id' => 'FeedEnabled']) ?>
                    <?= $this->Form->label('FeedEnabled', __('Enabled'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('caching_enabled', ['class' => 'form-check-input', 'id' => 'FeedCachingEnabled']) ?>
                    <?= $this->Form->label('FeedCachingEnabled', __('Caching enabled'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('lookup_visible', ['class' => 'form-check-input', 'id' => 'FeedLookupVisible']) ?>
                    <?= $this->Form->label('FeedLookupVisible', __('Lookup visible'), ['class' => 'form-check-label']) ?>
                </div>
            </div>
            <div class="col-md-4">
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('settings.disable_correlation', ['class' => 'form-check-input', 'id' => 'FeedSettingsDisableCorrelation']) ?>
                    <?= $this->Form->label('FeedSettingsDisableCorrelation', __('Disable correlation'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('settings.unpublish_event', ['class' => 'form-check-input', 'id' => 'FeedSettingsUnpublishEvent']) ?>
                    <?= $this->Form->label('FeedSettingsUnpublishEvent', __('Unpublish events'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('lock_events', ['class' => 'form-check-input', 'id' => 'FeedLockEvents']) ?>
                    <?= $this->Form->label('FeedLockEvents', __('Lock events'), ['class' => 'form-check-label']) ?>
                </div>
            </div>
            <div class="col-md-4">
                <div class="form-check form-switch mb-2 optionalField" id="PublishDiv" style="display:none;">
                    <?= $this->Form->checkbox('publish', ['class' => 'form-check-input', 'id' => 'FeedPublish']) ?>
                    <?= $this->Form->label('FeedPublish', __('Auto publish'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-check form-switch mb-2 optionalField" id="OverrideIdsDiv" style="display:none;">
                    <?= $this->Form->checkbox('override_ids', ['class' => 'form-check-input', 'id' => 'FeedOverrideIds']) ?>
                    <?= $this->Form->label('FeedOverrideIds', __('Override IDS flag'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-check form-switch mb-2 optionalField" id="DeltaMergeDiv" style="display:none;">
                    <?= $this->Form->checkbox('delta_merge', ['class' => 'form-check-input', 'id' => 'FeedDeltaMerge']) ?>
                    <?= $this->Form->label('FeedDeltaMerge', __('Delta merge'), ['class' => 'form-check-label']) ?>
                </div>
            </div>
        </div>

        <!-- ================= TARGET (freetext/csv) ================= -->
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="OrgcDiv" style="display:none;">
                <?= $this->Form->label('orgc_id', __('Creator organisation'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('orgc_id', $dropdownData['orgs'], [
                    'class' => 'form-select tom-select', 'value' => $orgcSelected, 'empty' => false,
                ]) ?>
            </div>
            <div class="col-md-6 mb-3 optionalField" id="TargetDiv" style="display:none;">
                <?= $this->Form->label('fixed_event', __('Target event'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('fixed_event', [1 => __('Fixed event'), 0 => __('New event each pull')], [
                    'class' => 'form-select', 'id' => 'FeedFixedEvent', 'value' => $fixedSelected, 'empty' => false,
                ]) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="TargetEventDiv" style="display:none;">
                <?= $this->Form->label('event_id', __('Target event ID'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('event_id', [
                    'class' => 'form-control', 'placeholder' => __('Leave blank unless you want to reuse an existing event.'),
                ]) ?>
            </div>
            <div class="col-md-6 mb-3 optionalField" id="settingsCommonExcluderegexDiv" style="display:none;">
                <?= $this->Form->label('settings.common.excluderegex', __('Exclusion regex'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('settings.common.excluderegex', [
                    'class' => 'form-control', 'value' => $excludeRegexVal,
                    'placeholder' => __('Regex pattern, for example: "/^https://myfeedurl/i'),
                ]) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-md-6 mb-3 optionalField" id="settingsCsvValueDiv" style="display:none;">
                <?= $this->Form->label('settings.csv.value', __('Value field(s) in the CSV'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('settings.csv.value', [
                    'class' => 'form-control', 'value' => $csvValueVal,
                    'placeholder' => __('2,3,4 (column position separated by commas)'),
                ]) ?>
            </div>
            <div class="col-md-6 mb-3 optionalField" id="settingsCsvDelimiterDiv" style="display:none;">
                <?= $this->Form->label('settings.csv.delimiter', __('Delimiter'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->text('settings.csv.delimiter', [
                    'class' => 'form-control', 'value' => $delimiterVal, 'placeholder' => ',',
                ]) ?>
            </div>
        </div>

        <!-- ================= DISTRIBUTION ================= -->
        <div class="fw-semibold mb-2 mt-2"><?= __('Distribution') ?></div>
        <div class="row">
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('distribution', __('Distribution'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('distribution', $dropdownData['distributionLevels'], [
                    'class' => 'form-select', 'id' => 'FeedDistribution', 'value' => $distSelected, 'empty' => false,
                ]) ?>
            </div>
            <div class="col-md-6 mb-3" id="SGContainer" style="display:none;">
                <?= $this->Form->label('sharing_group_id', __('Sharing group'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('sharing_group_id', $dropdownData['sharingGroups'], [
                    'class' => 'form-select tom-select', 'value' => $sgSelected, 'empty' => true,
                ]) ?>
            </div>
        </div>
        <div class="row">
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('tag_id', __('Default tag'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('tag_id', $dropdownData['tags'], [
                    'class' => 'form-select tom-select', 'value' => $tagSelected, 'empty' => false,
                ]) ?>
            </div>
            <div class="col-md-6 mb-3">
                <?= $this->Form->label('tag_collection_id', __('Default tag collection'), ['class' => 'form-label fw-semibold']) ?>
                <?= $this->Form->select('tag_collection_id', $dropdownData['tag_collections'], [
                    'class' => 'form-select tom-select', 'value' => $tagCollSelected, 'empty' => false,
                ]) ?>
            </div>
        </div>

        <!-- ================= FILTER RULES ================= -->
        <div class="fw-semibold mb-2 mt-2"><?= __('Filter rules') ?></div>
        <?php if (!empty($ruleSummary)): ?>
            <div class="bg-light border rounded p-2 mb-2">
                <?php foreach ($ruleSummary as $line): ?>
                    <div class="mb-1"><?= $line ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
        <div class="mb-3">
            <?= $this->Form->label('pull_rules', __('Pull rules (JSON)'), ['class' => 'form-label']) ?>
            <?= $this->Form->textarea('pull_rules', [
                'class' => 'form-control font-monospace', 'rows' => 6, 'spellcheck' => 'false',
                'value' => $rulesPretty,
            ]) ?>
            <div class="form-text">
                <?= __('Filter which events are pulled from the feed by tags/organisations (OR/NOT) and event-index parameters (url_params). Example: %s.', '<code>{"tags":{"OR":[],"NOT":[]},"orgs":{"OR":[],"NOT":[]},"url_params":""}</code>') ?>
            </div>
        </div>

        <!-- ACTIONS -->
        <div class="d-flex justify-content-end gap-3 mt-4">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal"><?= __('Cancel') ?></button>
            <?= $this->Form->button(
                '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save feed') : __('Add feed')),
                ['class' => 'btn btn-primary', 'escapeTitle' => false, 'type' => 'submit']
            ) ?>
        </div>

    </div>
</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var root = document;
    function el(id) { return root.getElementById(id); }
    function show(id) { var e = el(id); if (e) e.style.display = ''; }
    function hide(id) { var e = el(id); if (e) e.style.display = 'none'; }

    var optional = ['OrgcDiv', 'TargetDiv', 'TargetEventDiv', 'settingsCsvValueDiv',
        'settingsCsvDelimiterDiv', 'settingsCommonExcluderegexDiv', 'PublishDiv',
        'OverrideIdsDiv', 'DeltaMergeDiv'];

    function feedFormUpdate() {
        optional.forEach(hide);
        var fmt = el('FeedSourceFormat');
        var fmtVal = fmt ? fmt.value : '';
        if (fmtVal === 'freetext' || fmtVal === 'csv') {
            show('TargetDiv'); show('OrgcDiv'); show('OverrideIdsDiv');
            show('PublishDiv'); show('settingsCommonExcluderegexDiv');
            var fe = el('FeedFixedEvent');
            if (fe && fe.value != 0) { show('TargetEventDiv'); show('DeltaMergeDiv'); }
            if (fmtVal === 'csv') { show('settingsCsvValueDiv'); show('settingsCsvDelimiterDiv'); }
        }
        var src = el('FeedInputSource');
        if (src && src.value === 'local') { show('DeleteLocalFileDiv'); hide('HeadersDiv'); }
        else { hide('DeleteLocalFileDiv'); show('HeadersDiv'); }
        var dist = el('FeedDistribution');
        var sg = el('SGContainer');
        if (sg) sg.style.display = (dist && dist.value == 4) ? '' : 'none';
    }

    ['FeedSourceFormat', 'FeedFixedEvent', 'FeedInputSource', 'FeedDistribution'].forEach(function (id) {
        var e = el(id);
        if (e) e.addEventListener('change', feedFormUpdate);
    });
    feedFormUpdate();

    // Basic auth helper: append an Authorization: Basic header line.
    var toggle = el('feedBasicAuthToggle');
    if (toggle) {
        toggle.addEventListener('click', function () {
            var f = el('feedBasicAuthForm');
            if (f) f.style.display = (f.style.display === 'none' || !f.style.display) ? 'block' : 'none';
        });
    }
    var addBtn = el('feedBasicAuthAdd');
    if (addBtn) {
        addBtn.addEventListener('click', function () {
            var u = (el('feedBasicAuthUser') || {}).value || '';
            var p = (el('feedBasicAuthPass') || {}).value || '';
            var ta = el('FeedHeaders');
            if (!ta) return;
            var line = 'Authorization: Basic ' + btoa(u + ':' + p);
            ta.value = ta.value ? (ta.value.replace(/\s*$/, '') + '\n' + line) : line;
        });
    }
})();
</script>
