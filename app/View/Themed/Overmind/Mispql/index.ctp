<?php
/**
 * The query console: the writer on top, the latest result below, History
 * and Tables beside them. js/mispql/console.mjs assembles it.
 *
 * @var array $pack what MispQLLanguagePack builds for this user
 * @var array $history MispQLHistory entries
 * @var array|null $intelGraph set when the workspace dock boots: the grid's
 *                             rows can then be added to collections
 * @var array $inPlace which of MISP's views a cell opens in place:
 *                     {peeks, valueCard, reportReader}
 */
$this->set('headerTitle', __('MispQL Console'));
$this->set('headerBreadcrumb', [__('API'), 'MispQL']);
$this->set('headerActions', [
    [
        'url' => $baseurl . '/api/rest',
        'label' => __('REST Client'),
        'type' => 'navigate',
        'icon' => 'terminal',
    ],
]);

// A tag cell is an events index lane: its chips, +N and popover
echo $this->element('genericElements/assetLoader', [
    'css' => ['events-index-cards', 'events-index-table', 'mispql-console'],
    'js' => ['events-index-cards'],
]);

// Module imports carry no query string of their own, so each module's
// version goes through the import map.
// An object opens in place in the workspace's popover; the dock loads it, else the page does
if (empty($intelGraph)) {
    echo $this->element('intel_graph_working_text');
    echo $this->element('genericElements/assetLoader', [
        'css' => ['intel-graph-working'],
        'js' => ['intel-graph-working'],
    ]);
}

$asset = function ($path) use ($baseurl, $queryVersion) {
    $version = is_file(WWW_ROOT . $path) ? filemtime(WWW_ROOT . $path) : $queryVersion;
    return $baseurl . '/' . $path . '?v=' . $version;
};
$modules = [
    'client', 'console', 'inplace', 'popover', 'results', 'rewrite', 'selection', 'snippets', 'suggest', 'tokens',
    'util', 'writer',
];
$imports = [];
foreach ($modules as $module) {
    $path = 'js/mispql/' . $module . '.mjs';
    $imports[$baseurl . '/' . $path] = $asset($path);
}
// A report opens in the event page's reader, its scripts loaded on the first one opened
$inPlace = $inPlace ?? [];
if (!empty($inPlace['reportReader'])) {
    $inPlace['reportReader'] = [
        'css' => [$asset('css/event-overview.css')],
        'js' => array_map(function ($name) use ($asset) {
            return $asset('js/' . $name . '.js');
        }, ['markdown-it', 'font-awesome-helper', 'misp-report-markdown', 'event-report-reader']),
    ];
}
$entry = $imports[$baseurl . '/js/mispql/console.mjs'];
$jsonFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES;
?>
<div class="container-fluid pb-4 wb-layout" id="mql-console">
    <div class="row g-3 align-items-start">
        <div class="col-lg-4 col-xxl-3 order-2 order-lg-1">
            <div class="card wb-lib">
                <div class="p-2 pb-0">
                    <ul class="nav nav-pills nav-fill gap-1 small" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button type="button" role="tab" class="nav-link py-1 px-2 d-flex align-items-center justify-content-center gap-2 active" data-lib-tab="history" aria-selected="true" aria-controls="wb-list">
                                <?= __('History') ?> <span class="badge rounded-pill bg-body-secondary text-body-secondary" id="wb-hist-count">0</span>
                            </button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button type="button" role="tab" class="nav-link py-1 px-2 d-flex align-items-center justify-content-center gap-2" data-lib-tab="tables" aria-selected="false" aria-controls="wb-list">
                                <?= __('Tables') ?> <span class="badge rounded-pill bg-body-secondary text-body-secondary" id="wb-table-count">0</span>
                            </button>
                        </li>
                    </ul>
                </div>
                <div class="wb-filter">
                    <i class="fas fa-magnifying-glass" aria-hidden="true"></i>
                    <input type="search" class="form-control form-control-sm" id="wb-filter" placeholder="<?= __('Filter history') ?>" aria-label="<?= __('Filter') ?>">
                </div>
                <div class="wb-list" id="wb-list" role="tabpanel"></div>
            </div>
        </div>

        <div class="col-lg-8 col-xxl-9 order-1 order-lg-2 d-flex flex-column gap-3">
            <div class="card wb-writer-card">
                <div class="card-body">
                    <div class="wb-writer-top">
                        <span class="wb-writer-title">MispQL</span>
                        <span class="wb-statements" id="wb-statements"></span>
                        <div class="ms-auto d-flex gap-2 align-items-center">
                            <div class="dropdown" id="wb-examples">
                                <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false" aria-label="<?= __('Examples') ?>"><i class="fas fa-wand-magic-sparkles" aria-hidden="true"></i><span class="wb-btn-label"><?= __('Examples') ?></span></button>
                                <ul class="dropdown-menu dropdown-menu-end"></ul>
                            </div>
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="wb-clear" title="<?= __('Clear the writer') ?>" aria-label="<?= __('Clear') ?>"><i class="fas fa-eraser" aria-hidden="true"></i><span class="wb-btn-label"><?= __('Clear') ?></span></button>
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="wb-explain" title="<?= __('Show what the statement under the caret compiles to, without running it') ?>" aria-keyshortcuts="Control+Shift+Enter"><i class="fas fa-route" aria-hidden="true"></i><?= __('Explain') ?></button>
                            <button type="button" class="btn btn-primary btn-run" id="wb-run" title="<?= __('Run the statement under the caret') ?>" aria-keyshortcuts="Control+Enter">
                                <i class="fas fa-play" aria-hidden="true"></i><?= __('Run') ?> <kbd class="btn-run-keys" aria-hidden="true">Ctrl ↵</kbd>
                            </button>
                        </div>
                    </div>
                    <div id="wb-writer"></div>
                    <div class="mql-status">
                        <div id="wb-status" class="d-flex min-w-0" aria-live="polite"></div>
                        <div class="mql-hints">
                            <span><kbd>Ctrl</kbd><kbd>Space</kbd> <?= __('suggest') ?></span>
                            <span><kbd>Ctrl</kbd><kbd>↵</kbd> <?= __('run statement') ?></span>
                            <span><kbd>Ctrl</kbd><kbd>Shift</kbd><kbd>↵</kbd> <?= __('explain') ?></span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card wb-result" id="wb-result" aria-live="polite"></div>
        </div>
    </div>
</div>
<?php if (!empty($intelGraph)): ?>
<div class="ms-float d-none" id="mql-selbar" role="region" aria-label="<?= __('Selected rows') ?>"
     data-note="<?= h(__('%s of %s rows shown; add a LIMIT to work on the rest page by page')) ?>">
    <div class="p-2 border rounded bg-light d-flex align-items-center gap-2 flex-wrap">
        <span class="ms-count" id="mql-sel-count" data-template="<?= h(__('%s selected')) ?>"></span>
        <span class="ms-sep" aria-hidden="true"></span>
        <?= $this->element('intel_graph_add', [
            'id' => 'mql-sel-add',
            'variant' => 'short',
            'btnClass' => 'btn-sm btn-analystGraph',
            'title' => __('Add the selected to the workspace'),
            'stateless' => true,
        ]) ?>
        <span class="small text-muted mql-sel-note" id="mql-sel-note" hidden></span>
        <span class="ms-sep" aria-hidden="true"></span>
        <button type="button" class="btn btn-sm btn-link ms-clear" id="mql-sel-clear"><?= __('Clear selection') ?></button>
    </div>
</div>
<?php endif; ?>
<script type="application/json" id="mispql-language-pack"><?= json_encode($pack, $jsonFlags) ?></script>
<script type="application/json" id="mispql-history"><?= json_encode($history, $jsonFlags) ?></script>
<script type="application/json" id="mispql-in-place"><?= json_encode($inPlace, $jsonFlags) ?></script>
<?php if (!empty($inPlace['reportReader'])): ?>
<?= $this->element('Events/View/report_reader') ?>
<?php endif; ?>
<script type="importmap"><?= json_encode(['imports' => $imports], $jsonFlags) ?></script>
<script type="module" src="<?= h($entry) ?>"></script>
