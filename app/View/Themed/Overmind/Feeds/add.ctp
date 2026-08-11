<?php
// Overmind BS5 add/edit form for a Feed. Rendered layout-less as a modal
// fragment (opened via openModal). Self-contained: under Overmind only
// mispOvermind.js is loaded, so the legacy misp.js helpers (feedFormUpdate /
// checkSharingGroup / add_basic_auth) are re-implemented inline below.
//
$isEdit = $this->request->params['action'] === 'edit';
$reqFeed = $this->request->data['Feed'] ?? [];
$entityFeed = $entity['Feed'] ?? [];

$distSelected = $reqFeed['distribution'] ?? 3;
$orgcSelected = $reqFeed['orgc_id'] ?? ($isEdit ? null : ($me['org_id'] ?? null));
$sgSelected = $reqFeed['sharing_group_id'] ?? null;
$tagSelected = $reqFeed['tag_id'] ?? '0';
$tagCollSelected = $reqFeed['tag_collection_id'] ?? '0';
$fixedSelected = $reqFeed['fixed_event'] ?? 0;
$sourceFormatSel = $reqFeed['source_format'] ?? 'freetext';
$inputSourceSel = $reqFeed['input_source'] ?? 'network';
$delimiterVal = $reqFeed['settings']['csv']['delimiter'] ?? ',';
$csvValueVal = $reqFeed['settings']['csv']['value'] ?? '';
$excludeRegexVal = $reqFeed['settings']['common']['excluderegex'] ?? '';

// Initial pull_rules JSON, pretty-printed; the reading of it is built client
// side so it follows what is being typed.
if ($isEdit) {
    $rulesRaw = $reqFeed['pull_rules'] ?? ($entityFeed['rules'] ?? '');
} else {
    $rulesRaw = $defaultPullRules ?? '';
}
$rulesDecoded = !empty($rulesRaw) ? json_decode($rulesRaw, true) : null;
$rulesPretty = is_array($rulesDecoded)
    ? json_encode($rulesDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    : (string)$rulesRaw;

// What each source format and input source means, shown live under the picker.
$formatMeta = [
    'misp' => [
        'icon' => 'misp-icon misp-icon-misp misp-simple',
        'hint' => __('The remote end serves MISP events as JSON; they are pulled as whole events.'),
    ],
    'freetext' => [
        'icon' => 'fas fa-align-left',
        'hint' => __('Indicators are extracted from arbitrary text and land as attributes.'),
    ],
    'csv' => [
        'icon' => 'fas fa-table-cells',
        'hint' => __('Indicators are read from the columns you point at below.'),
    ],
];
$sourceMeta = [
    'network' => [
        'icon' => 'fas fa-globe',
        'hint' => __('Fetched over HTTP(S) from the URL below.'),
    ],
    'local' => [
        'icon' => 'fas fa-folder-open',
        'hint' => __('Read from a path on this server rather than fetched.'),
    ],
];

// Booleans, in the order they are laid out. `div` is the wrapper id the
// format-driven show/hide logic below keys on.
$options = [
    [
        'field' => 'enabled', 'id' => 'FeedEnabled',
        'label' => __('Enabled'), 'hint' => __('Pull this feed on the scheduled run'),
        'icon' => 'fas fa-power-off', 'accent' => '#198754',
    ],
    [
        'field' => 'caching_enabled', 'id' => 'FeedCachingEnabled',
        'label' => __('Caching enabled'), 'hint' => __('Cache the values for correlation without importing'),
        'icon' => 'fas fa-database', 'accent' => '#0d6efd',
    ],
    [
        'field' => 'lookup_visible', 'id' => 'FeedLookupVisible',
        'label' => __('Lookup visible'), 'hint' => __('Show hits on this feed to every user'),
        'icon' => 'fas fa-eye', 'accent' => '#0dcaf0',
    ],
    [
        'field' => 'Feed.settings.disable_correlation', 'id' => 'FeedSettingsDisableCorrelation',
        'label' => __('Disable correlation'), 'hint' => __('Imported attributes never correlate'),
        'icon' => 'fas fa-link-slash', 'accent' => '#6c757d',
    ],
    [
        'field' => 'Feed.settings.unpublish_event', 'id' => 'FeedSettingsUnpublishEvent',
        'label' => __('Unpublish events'), 'hint' => __('Leave the touched events unpublished'),
        'icon' => 'fas fa-rotate-left', 'accent' => '#6c757d',
    ],
    [
        'field' => 'lock_events', 'id' => 'FeedLockEvents',
        'label' => __('Lock events'), 'hint' => __('Mark created events as locked'),
        'icon' => 'fas fa-lock', 'accent' => '#6c757d',
    ],
    [
        'field' => 'publish', 'id' => 'FeedPublish', 'div' => 'PublishDiv',
        'label' => __('Auto publish'), 'hint' => __('Publish the event right after the pull'),
        'icon' => 'fas fa-bullhorn', 'accent' => '#1892B1',
    ],
    [
        'field' => 'override_ids', 'id' => 'FeedOverrideIds', 'div' => 'OverrideIdsDiv',
        'label' => __('Override IDS flag'), 'hint' => __('Import the values with to_ids turned off'),
        'icon' => 'fas fa-shield-halved', 'accent' => '#ffc107',
    ],
    [
        'field' => 'delta_merge', 'id' => 'FeedDeltaMerge', 'div' => 'DeltaMergeDiv',
        'label' => __('Delta merge'), 'hint' => __('Drop the values that vanished from the feed'),
        'icon' => 'fas fa-code-compare', 'accent' => '#fd7e14',
    ],
    [
        'field' => 'delete_local_file', 'id' => 'FeedDeleteLocalFile', 'div' => 'DeleteLocalFileDiv',
        'label' => __('Delete local file'), 'hint' => __('Remove the source file once it is pulled'),
        'icon' => 'fas fa-trash', 'accent' => '#dc3545',
    ],
];

$localFeedDisabled = !empty(Configure::read('Security.disable_local_feed_access'));

echo $this->Form->create('Feed', [
    'url' => $baseurl . '/feeds/' . ($isEdit ? 'edit/' . h($feedId ?? ($reqFeed['id'] ?? '')) : 'add'),
    'id' => 'feedForm',
    'class' => 'feed-form',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Feeds') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Feed') : __('Add Feed') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('A source that can be imported as events or merely cached, so its values light up in correlations.') ?>
        </p>
    </div>
    <i class="fas fa-rss text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <?php if ($localFeedDisabled): ?>
            <div class="alert alert-warning d-flex align-items-start gap-2 mb-0"
                 role="alert" style="font-size:.8rem;">
                <i class="fas fa-triangle-exclamation mt-1"></i>
                <div>
                    <?= __('Local feeds are disabled by policy. To re-enable the feature, set Security.disable_local_feed_access to false in the server settings (CLI only).') ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Feed Name') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'FeedName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. CIRCL OSINT feed'),
                'autocomplete' => 'off',
            ]) ?>
        </div>

        <!-- ── SOURCE ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Source') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>

            <div class="row g-3">
                <div class="col-md-4">
                    <label class="form-label text-muted mb-1" for="FeedProvider"
                           style="font-size:.75rem;">
                        <i class="fas fa-building me-1" style="font-size:.7rem;"></i>
                        <?= __('Provider') ?>
                    </label>
                    <?= $this->Form->text('provider', [
                        'id' => 'FeedProvider',
                        'class' => 'form-control',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => __('Who publishes it'),
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-4">
                    <label class="form-label text-muted mb-1" for="FeedInputSource"
                           style="font-size:.75rem;">
                        <?= __('Input source') ?>
                    </label>
                    <?= $this->Form->select('input_source', $dropdownData['inputSources'], [
                        'class' => 'form-select',
                        'id' => 'FeedInputSource',
                        'value' => $inputSourceSel,
                        'empty' => false,
                    ]) ?>
                </div>
                <div class="col-md-4">
                    <label class="form-label text-muted mb-1" for="FeedSourceFormat"
                           style="font-size:.75rem;">
                        <?= __('Source format') ?>
                    </label>
                    <?= $this->Form->select('source_format', $dropdownData['feedTypes'], [
                        'class' => 'form-select',
                        'id' => 'FeedSourceFormat',
                        'value' => $sourceFormatSel,
                        'empty' => false,
                    ]) ?>
                </div>
            </div>

            <div class="d-flex align-items-start gap-1 mt-2 text-muted"
                 id="FeedSourceHint" style="font-size:.75rem;"></div>

            <div class="mt-3">
                <label class="form-label text-muted mb-1" for="FeedUrl"
                       style="font-size:.75rem;">
                    <span id="FeedUrlLabel"><?= __('URL') ?></span>
                </label>
                <div class="input-group">
                    <span class="input-group-text bg-transparent"
                          style="border-color:#d8dde3;">
                        <i class="fas fa-link text-muted" id="FeedUrlIcon"
                           style="font-size:.8rem;"></i>
                    </span>
                    <?= $this->Form->text('url', [
                        'id' => 'FeedUrl',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'placeholder' => 'https://example.org/feed.json',
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── HEADERS (network only) ──────────────────────────── -->
        <div class="w-100 px-2" id="HeadersDiv">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Request Headers') ?>
            </div>
            <?= $this->Form->textarea('headers', [
                'class' => 'w-100 rounded-2 p-3',
                'id' => 'FeedHeaders',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.85rem; min-height:90px;'
                    . ' color:inherit; font-family:monospace;',
                'rows' => 3,
                'placeholder' => "Authorization: Bearer …\nX-Custom-Header: value",
            ]) ?>
            <div class="d-flex align-items-center justify-content-between gap-2 mt-1">
                <div class="d-flex align-items-center gap-1 text-muted"
                     style="font-size:.75rem;">
                    <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                    <?= __('One "headername: value" pair per line.') ?>
                </div>
                <button type="button" class="btn btn-outline-secondary btn-sm"
                        id="feedBasicAuthToggle"
                        style="font-size:.7rem; padding:.15rem .5rem;">
                    <i class="fas fa-key me-1"></i><?= __('Add basic auth') ?>
                </button>
            </div>
            <div id="feedBasicAuthForm" class="border rounded p-3 mt-2"
                 style="display:none; border-color:#d8dde3 !important;">
                <div class="row g-2">
                    <div class="col-md-5">
                        <input type="text" class="form-control form-control-sm"
                               id="feedBasicAuthUser" autocomplete="off"
                               placeholder="<?= __('Username') ?>">
                    </div>
                    <div class="col-md-5">
                        <input type="text" class="form-control form-control-sm"
                               id="feedBasicAuthPass" autocomplete="off"
                               placeholder="<?= __('Password') ?>">
                    </div>
                    <div class="col-md-2">
                        <button type="button" class="btn btn-sm btn-primary w-100"
                                id="feedBasicAuthAdd"><?= __('Add') ?></button>
                    </div>
                </div>
                <div class="text-muted mt-2" style="font-size:.72rem;">
                    <?= __('Encoded into an Authorization header — the credentials are not stored separately.') ?>
                </div>
            </div>
        </div>

        <!-- ── OPTIONS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Options') ?>
            </div>
            <div class="row g-2">
                <?php foreach ($options as $option): ?>
                    <div class="col-md-4<?= !empty($option['div']) ? ' optionalField' : '' ?>"
                         <?= !empty($option['div'])
                             ? 'id="' . h($option['div']) . '" style="display:none;"'
                             : '' ?>>
                        <label class="d-flex align-items-center gap-3 rounded-2 p-3
                                      h-100 w-100 user-select-none mb-0"
                               data-option-card
                               data-accent="<?= h($option['accent']) ?>"
                               style="cursor:pointer; transition:border-color .15s;
                                      border:1px solid #dee2e6;">
                            <?= $this->Form->checkbox($option['field'], [
                                'id' => $option['id'],
                                'class' => 'form-check-input flex-shrink-0',
                                'style' => 'margin-top:0;',
                            ]) ?>
                            <div class="flex-fill">
                                <div class="fw-bold text-uppercase"
                                     style="font-size:.72rem; letter-spacing:.06em;
                                            line-height:1.2;">
                                    <?= h($option['label']) ?>
                                </div>
                                <div class="text-muted"
                                     style="font-size:.74rem; margin-top:.2rem;
                                            line-height:1.3;">
                                    <?= h($option['hint']) ?>
                                </div>
                            </div>
                            <i class="<?= h($option['icon']) ?>" data-option-icon
                               style="font-size:.95rem; transition:color .15s;
                                      color:#adb5bd;"></i>
                        </label>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- ── PARSING TARGET (freetext / csv) ─────────────────── -->
        <div class="w-100 px-2 optionalField" id="TargetSection" style="display:none;">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Parsing Target') ?>
            </div>
            <div class="row g-3">
                <div class="col-md-6 optionalField" id="OrgcDiv" style="display:none;">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <i class="fas fa-building me-1" style="font-size:.7rem;"></i>
                        <?= __('Creator organisation') ?>
                    </label>
                    <?= $this->Form->select('orgc_id', $dropdownData['orgs'], [
                        'class' => 'form-select tom-select',
                        'value' => $orgcSelected,
                        'empty' => false,
                    ]) ?>
                </div>
                <div class="col-md-6 optionalField" id="TargetDiv" style="display:none;">
                    <label class="form-label text-muted mb-1" for="FeedFixedEvent"
                           style="font-size:.75rem;">
                        <i class="misp-icon misp-icon-event misp-simple me-1"></i>
                        <?= __('Target event') ?>
                    </label>
                    <?= $this->Form->select('fixed_event', [
                        1 => __('Fixed event'),
                        0 => __('New event each pull'),
                    ], [
                        'class' => 'form-select',
                        'id' => 'FeedFixedEvent',
                        'value' => $fixedSelected,
                        'empty' => false,
                    ]) ?>
                </div>
                <div class="col-md-6 optionalField" id="TargetEventDiv" style="display:none;">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <?= __('Target event ID') ?>
                    </label>
                    <?php
                    /* Two different keys reach the stored event_id: add()
                     * overwrites it from 'target_event', while edit() only
                     * whitelists 'event_id'. Post the one the current action
                     * reads, or the field is silently dropped. */
                    echo $this->Form->text($isEdit ? 'event_id' : 'target_event', [
                        'id' => 'FeedTargetEvent',
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'value' => $reqFeed['event_id'] ?? null,
                        'placeholder' => __('Leave blank to let the pull create it'),
                        'autocomplete' => 'off',
                    ]);
                    ?>
                </div>
                <div class="col-md-6 optionalField" id="settingsCommonExcluderegexDiv"
                     style="display:none;">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <?= __('Exclusion regex') ?>
                    </label>
                    <?= $this->Form->text('Feed.settings.common.excluderegex', [
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'value' => $excludeRegexVal,
                        'placeholder' => '/^https:\/\/example\.org/i',
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-6 optionalField" id="settingsCsvValueDiv"
                     style="display:none;">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <?= __('Value column(s)') ?>
                    </label>
                    <?= $this->Form->text('Feed.settings.csv.value', [
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'value' => $csvValueVal,
                        'placeholder' => __('e.g. 2,3,4'),
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
                <div class="col-md-6 optionalField" id="settingsCsvDelimiterDiv"
                     style="display:none;">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <?= __('Delimiter') ?>
                    </label>
                    <?= $this->Form->text('Feed.settings.csv.delimiter', [
                        'class' => 'form-control font-monospace',
                        'style' => 'border-color:#d8dde3;',
                        'value' => $delimiterVal,
                        'placeholder' => ',',
                        'autocomplete' => 'off',
                    ]) ?>
                </div>
            </div>
        </div>

        <!-- ── DISTRIBUTION ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Distribution / Sharing Group') ?>
            </div>
            <div class="d-flex gap-3">
                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $dropdownData['distributionLevels'], [
                        'class' => 'form-select',
                        'id' => 'FeedDistribution',
                        'value' => $distSelected,
                        'empty' => false,
                    ]) ?>
                </div>
                <div class="flex-fill" id="SGContainer" style="display:none;">
                    <?= $this->Form->select('sharing_group_id', $dropdownData['sharingGroups'], [
                        'class' => 'form-select tom-select',
                        'value' => $sgSelected,
                        'empty' => true,
                    ]) ?>
                </div>
            </div>

            <div class="row g-3 mt-1">
                <div class="col-md-6">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <i class="misp-icon misp-icon-tag misp-simple me-1"></i>
                        <?= __('Default tag') ?>
                    </label>
                    <?= $this->Form->select('tag_id', $dropdownData['tags'], [
                        'class' => 'form-select tom-select',
                        'value' => $tagSelected,
                        'empty' => false,
                    ]) ?>
                </div>
                <div class="col-md-6">
                    <label class="form-label text-muted mb-1" style="font-size:.75rem;">
                        <i class="fas fa-layer-group me-1" style="font-size:.7rem;"></i>
                        <?= __('Default tag collection') ?>
                    </label>
                    <?= $this->Form->select('tag_collection_id', $dropdownData['tag_collections'], [
                        'class' => 'form-select tom-select',
                        'value' => $tagCollSelected,
                        'empty' => false,
                    ]) ?>
                </div>
            </div>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Attached to everything this feed brings in.') ?>
            </div>
        </div>

        <!-- ── PULL FILTER RULES ───────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="text-primary fw-bold text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Pull Filter Rules') ?>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <span id="feedRulesStatus" class="badge bg-secondary"
                          style="font-size:.65rem;"></span>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="feedRulesFormatBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Format') ?>
                    </button>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="feedRulesResetBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-rotate-left me-1"></i><?= __('Reset') ?>
                    </button>
                </div>
            </div>

            <?= $this->Form->textarea('pull_rules', [
                'id' => 'FeedPullRules',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.85rem; min-height:150px;'
                    . ' color:inherit; font-family:monospace;'
                    . ' white-space:pre; overflow-x:auto;',
                'rows' => 8,
                'spellcheck' => 'false',
                'value' => $rulesPretty,
            ]) ?>
            <div id="feedRulesError" class="d-none text-danger
                        d-flex align-items-center gap-1 mt-1"
                 style="font-size:.75rem;"></div>

            <!-- Reading of the rules, rebuilt as they are typed -->
            <div class="mt-2 d-none" id="feedRulesReadingWrap">
                <div class="border rounded p-2" id="feedRulesReading"
                     style="border-color:#d8dde3 !important; font-size:.78rem;"></div>
            </div>

            <div class="d-flex align-items-start gap-2 rounded-2 p-2 mt-2 small"
                 style="background:rgba(24,146,177,.05);
                        border:1px solid rgba(24,146,177,.25);">
                <i class="fas fa-circle-info text-primary mt-1"
                   style="font-size:.7rem;"></i>
                <div class="text-muted">
                    <?= __('%s and %s take tag or organisation names under %s and %s; %s is appended to the event index query.', '<code>tags</code>', '<code>orgs</code>', '<code>OR</code>', '<code>NOT</code>', '<code>url_params</code>') ?>
                    <?php if (!empty($supportedUrlparams)): ?>
                        <br>
                        <?= __('Supported url_params filters') ?>:
                        <?php foreach ($supportedUrlparams as $param): ?>
                            <code><?= h($param) ?></code>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($feedId)): ?>
                <?= __('Feed') ?>:
                <strong class="text-body">#<?= h($feedId) ?></strong>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('A feed can be previewed from the index before it is pulled.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Feed')),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                    'type' => 'submit',
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var FORMAT_META = <?= json_encode($formatMeta, JSON_FORCE_OBJECT
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var SOURCE_META = <?= json_encode($sourceMeta, JSON_FORCE_OBJECT
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var DEFAULT_RULES = <?= json_encode($defaultPullRules ?? '{}',
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var L = {
        url: <?= json_encode(__('URL')) ?>,
        path: <?= json_encode(__('Path on this server')) ?>,
        urlPlaceholder: <?= json_encode('https://example.org/feed.json') ?>,
        pathPlaceholder: <?= json_encode('/var/lib/misp/feed.txt') ?>,
        nameRequired: <?= json_encode(__('Please provide a name for the feed.')) ?>,
        sourceRequired: <?= json_encode(__('Please provide the URL or path of the feed.')) ?>,
        providerRequired: <?= json_encode(__('Please provide the name of the provider.')) ?>,
        rulesEmpty: <?= json_encode(__('No filtering — everything is pulled')) ?>,
        rulesValid: <?= json_encode(__('Valid')) ?>,
        rulesInvalid: <?= json_encode(__('Invalid JSON')) ?>,
        rulesUnknown: <?= json_encode(__('Unknown key')) ?>,
        objectExpected: <?= json_encode(__('The rules have to be a JSON object.')) ?>,
        unknownKey: <?= json_encode(__('"%s" is not one of tags, orgs or url_params.')) ?>,
        unknownBool: <?= json_encode(__('"%s" only takes OR and NOT.')) ?>,
        listExpected: <?= json_encode(__('%s has to be a list of names.')) ?>,
        stringExpected: <?= json_encode(__('url_params has to be a string.')) ?>,
        anyOf: <?= json_encode(__('any of')) ?>,
        noneOf: <?= json_encode(__('none of')) ?>,
        query: <?= json_encode(__('Index query')) ?>
    };
    var RULE_KEYS = ['tags', 'orgs', 'url_params'];
    var BOOLS = ['OR', 'NOT'];

    function el(id) { return document.getElementById(id); }
    function show(id) { var e = el(id); if (e) { e.style.display = ''; } }
    function hide(id) { var e = el(id); if (e) { e.style.display = 'none'; } }

    /* ── Format / input source: show what applies, say what it means ── */
    var optional = ['OrgcDiv', 'TargetDiv', 'TargetEventDiv', 'settingsCsvValueDiv',
        'settingsCsvDelimiterDiv', 'settingsCommonExcluderegexDiv', 'PublishDiv',
        'OverrideIdsDiv', 'DeltaMergeDiv', 'TargetSection'];

    function refreshHint() {
        var hintEl = el('FeedSourceHint');
        if (!hintEl) { return; }
        var fmt = el('FeedSourceFormat');
        var src = el('FeedInputSource');
        var fmtMeta = FORMAT_META[fmt ? fmt.value : ''] || null;
        var srcMeta = SOURCE_META[src ? src.value : ''] || null;
        hintEl.innerHTML = '';
        [srcMeta, fmtMeta].forEach(function (meta) {
            if (!meta) { return; }
            var item = document.createElement('span');
            item.className = 'd-inline-flex align-items-center gap-1 me-3';
            var icon = document.createElement('i');
            icon.className = meta.icon;
            icon.style.fontSize = '.7rem';
            item.appendChild(icon);
            item.appendChild(document.createTextNode(meta.hint));
            hintEl.appendChild(item);
        });
    }

    function feedFormUpdate() {
        optional.forEach(hide);
        var fmt = el('FeedSourceFormat');
        var fmtVal = fmt ? fmt.value : '';
        if (fmtVal === 'freetext' || fmtVal === 'csv') {
            show('TargetSection');
            show('TargetDiv'); show('OrgcDiv'); show('OverrideIdsDiv');
            show('PublishDiv'); show('settingsCommonExcluderegexDiv');
            var fe = el('FeedFixedEvent');
            if (fe && fe.value != 0) { show('TargetEventDiv'); show('DeltaMergeDiv'); }
            if (fmtVal === 'csv') { show('settingsCsvValueDiv'); show('settingsCsvDelimiterDiv'); }
        }

        var src = el('FeedInputSource');
        var isLocal = src && src.value === 'local';
        if (isLocal) { show('DeleteLocalFileDiv'); hide('HeadersDiv'); }
        else { hide('DeleteLocalFileDiv'); show('HeadersDiv'); }

        /* The URL field is a path when the source is local — say so */
        var urlLabel = el('FeedUrlLabel');
        var urlIcon = el('FeedUrlIcon');
        var urlInput = el('FeedUrl');
        if (urlLabel) { urlLabel.textContent = isLocal ? L.path : L.url; }
        if (urlIcon) {
            urlIcon.className = (isLocal ? 'fas fa-folder-open' : 'fas fa-link')
                + ' text-muted';
            urlIcon.style.fontSize = '.8rem';
        }
        if (urlInput) {
            urlInput.setAttribute('placeholder',
                isLocal ? L.pathPlaceholder : L.urlPlaceholder);
        }

        var dist = el('FeedDistribution');
        var sg = el('SGContainer');
        if (sg) { sg.style.display = (dist && dist.value == 4) ? '' : 'none'; }

        refreshHint();
        refreshCards();
    }

    ['FeedSourceFormat', 'FeedFixedEvent', 'FeedInputSource'].forEach(function (id) {
        var e = el(id);
        if (e) { e.addEventListener('change', feedFormUpdate); }
    });

    /* Distribution keeps the canonical icons/tints of the theme */
    if (typeof initDistributionSelect === 'function') {
        initDistributionSelect('FeedDistribution', function () { feedFormUpdate(); });
    } else {
        var distEl = el('FeedDistribution');
        if (distEl) { distEl.addEventListener('change', feedFormUpdate); }
    }

    /* ── Option cards ── */
    function paintCard(card) {
        var box = card.querySelector('input[type="checkbox"]');
        var icon = card.querySelector('[data-option-icon]');
        var accent = card.dataset.accent || '#0d6efd';
        if (!box) { return; }
        card.style.borderColor = box.checked ? accent : '#dee2e6';
        if (icon) { icon.style.color = box.checked ? accent : '#adb5bd'; }
    }
    function refreshCards() {
        document.querySelectorAll('[data-option-card]').forEach(paintCard);
    }
    document.querySelectorAll('[data-option-card]').forEach(function (card) {
        var box = card.querySelector('input[type="checkbox"]');
        if (box) { box.addEventListener('change', function () { paintCard(card); }); }
    });

    /* ── Basic auth helper: append an Authorization line ── */
    var toggle = el('feedBasicAuthToggle');
    if (toggle) {
        toggle.addEventListener('click', function () {
            var f = el('feedBasicAuthForm');
            if (f) {
                f.style.display = (f.style.display === 'none' || !f.style.display)
                    ? 'block' : 'none';
            }
        });
    }
    var addBtn = el('feedBasicAuthAdd');
    if (addBtn) {
        addBtn.addEventListener('click', function () {
            var u = (el('feedBasicAuthUser') || {}).value || '';
            var p = (el('feedBasicAuthPass') || {}).value || '';
            var ta = el('FeedHeaders');
            if (!ta) { return; }
            var line = 'Authorization: Basic ' + btoa(u + ':' + p);
            ta.value = ta.value ? (ta.value.replace(/\s*$/, '') + '\n' + line) : line;
        });
    }

    /* ── Pull rules: validity, reading, formatting ── */
    var rulesEl = el('FeedPullRules');
    var statusEl = el('feedRulesStatus');
    var errorEl = el('feedRulesError');
    var readingEl = el('feedRulesReading');
    var readingWrap = el('feedRulesReadingWrap');

    function setStatus(kind, text) {
        if (!statusEl) { return; }
        statusEl.className = 'badge bg-' + kind;
        statusEl.style.fontSize = '.65rem';
        statusEl.textContent = text;
    }

    function setError(message) {
        if (!errorEl) { return; }
        if (!message) {
            errorEl.classList.add('d-none');
            errorEl.textContent = '';
            return;
        }
        errorEl.classList.remove('d-none');
        errorEl.innerHTML = '';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        errorEl.appendChild(icon);
        errorEl.appendChild(document.createTextNode(message));
    }

    /* First thing Feed::checkEventAgainstRules() would not understand */
    function findProblem(rules) {
        var keys = Object.keys(rules);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            if (RULE_KEYS.indexOf(key) === -1) {
                return L.unknownKey.replace('%s', key);
            }
            if (key === 'url_params') {
                if (typeof rules[key] !== 'string') { return L.stringExpected; }
                continue;
            }
            var scope = rules[key];
            if (!scope || typeof scope !== 'object' || Array.isArray(scope)) {
                return L.unknownBool.replace('%s', key);
            }
            var bools = Object.keys(scope);
            for (var j = 0; j < bools.length; j++) {
                if (BOOLS.indexOf(bools[j]) === -1) {
                    return L.unknownBool.replace('%s', key);
                }
                if (!Array.isArray(scope[bools[j]])) {
                    return L.listExpected.replace('%s', key + '.' + bools[j]);
                }
            }
        }
        return null;
    }

    function pill(text, bool) {
        var badge = document.createElement('span');
        badge.className = 'badge me-1 ' + (bool === 'NOT' ? 'text-bg-danger' : 'text-bg-success');
        badge.style.fontSize = '.65rem';
        badge.textContent = text;
        return badge;
    }

    function buildReading(rules) {
        var frag = document.createDocumentFragment();
        var any = false;
        ['tags', 'orgs'].forEach(function (scope) {
            if (!rules[scope]) { return; }
            BOOLS.forEach(function (bool) {
                var list = rules[scope][bool];
                if (!Array.isArray(list) || !list.length) { return; }
                any = true;
                var row = document.createElement('div');
                row.className = 'd-flex align-items-baseline gap-2 mb-1';
                var label = document.createElement('span');
                label.className = 'fw-semibold text-nowrap';
                label.textContent = scope + ' ' + (bool === 'NOT' ? L.noneOf : L.anyOf);
                row.appendChild(label);
                var wrap = document.createElement('span');
                list.forEach(function (value) { wrap.appendChild(pill(String(value), bool)); });
                row.appendChild(wrap);
                frag.appendChild(row);
            });
        });
        if (rules.url_params) {
            any = true;
            var row = document.createElement('div');
            row.className = 'd-flex align-items-baseline gap-2';
            var label = document.createElement('span');
            label.className = 'fw-semibold text-nowrap';
            label.textContent = L.query;
            var code = document.createElement('code');
            code.textContent = String(rules.url_params);
            row.appendChild(label);
            row.appendChild(code);
            frag.appendChild(row);
        }
        return any ? frag : null;
    }

    function refreshRules() {
        if (!rulesEl) { return; }
        var raw = rulesEl.value.trim();
        if (readingWrap) { readingWrap.classList.add('d-none'); }
        if (!raw) {
            setStatus('secondary', L.rulesEmpty);
            setError(null);
            return;
        }
        var parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            setStatus('danger', L.rulesInvalid);
            setError(e.message);
            return;
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            setStatus('danger', L.rulesInvalid);
            setError(L.objectExpected);
            return;
        }
        var problem = findProblem(parsed);
        setStatus(problem ? 'warning' : 'success', problem ? L.rulesUnknown : L.rulesValid);
        setError(problem);

        var reading = buildReading(parsed);
        if (reading && readingEl && readingWrap) {
            readingEl.innerHTML = '';
            readingEl.appendChild(reading);
            readingWrap.classList.remove('d-none');
        } else if (!problem) {
            setStatus('secondary', L.rulesEmpty);
        }
    }

    if (rulesEl) { rulesEl.addEventListener('input', refreshRules); }
    var fmtBtn = el('feedRulesFormatBtn');
    if (fmtBtn) {
        fmtBtn.addEventListener('click', function () {
            try {
                rulesEl.value = JSON.stringify(JSON.parse(rulesEl.value), null, 4);
            } catch (e) { /* refreshRules() reports it */ }
            refreshRules();
        });
    }
    var resetBtn = el('feedRulesResetBtn');
    if (resetBtn) {
        resetBtn.addEventListener('click', function () {
            try {
                rulesEl.value = JSON.stringify(JSON.parse(DEFAULT_RULES), null, 4);
            } catch (e) {
                rulesEl.value = DEFAULT_RULES;
            }
            refreshRules();
        });
    }

    /* ── The three fields the model needs ── */
    var form = el('feedForm');
    if (form) {
        var required = [
            { el: el('FeedName'), message: L.nameRequired, underlined: true },
            { el: el('FeedProvider'), message: L.providerRequired, underlined: false },
            { el: el('FeedUrl'), message: L.sourceRequired, underlined: false }
        ];

        function fieldError(entry, show) {
            var target = entry.el;
            if (!target) { return; }
            var errorId = target.id + 'Error';
            var existing = el(errorId);
            var property = entry.underlined ? 'border-bottom-color' : 'border-color';
            if (!show) {
                target.style.setProperty(property, '#d8dde3', 'important');
                if (existing) { existing.remove(); }
                return;
            }
            target.style.setProperty(property, '#dc3545', 'important');
            if (existing) { return; }
            var msg = document.createElement('div');
            msg.id = errorId;
            msg.className = 'text-danger d-flex align-items-center gap-1';
            msg.style.fontSize = '.75rem';
            msg.style.marginTop = '.35rem';
            var icon = document.createElement('i');
            icon.className = 'fas fa-circle-exclamation';
            msg.appendChild(icon);
            msg.appendChild(document.createTextNode(entry.message));
            /* The URL sits in an input-group, so hang the message off it */
            var anchor = target.closest('.input-group') || target;
            anchor.parentNode.insertBefore(msg, anchor.nextSibling);
        }

        form.addEventListener('submit', function (e) {
            var firstEmpty = null;
            required.forEach(function (entry) {
                if (!entry.el) { return; }
                var empty = !entry.el.value.trim();
                fieldError(entry, empty);
                if (empty && !firstEmpty) { firstEmpty = entry.el; }
            });
            if (firstEmpty) {
                e.preventDefault();
                e.stopPropagation();
                firstEmpty.focus();
            }
        });

        required.forEach(function (entry) {
            if (!entry.el) { return; }
            entry.el.addEventListener('input', function () {
                if (entry.el.value.trim()) { fieldError(entry, false); }
            });
        });
    }

    feedFormUpdate();
    refreshRules();
})();
</script>
