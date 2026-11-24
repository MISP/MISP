<?php
/**
 * The query console: the writer on top, the latest result below, History
 * and Tables beside them. js/mispql/console.mjs assembles it.
 *
 * @var array $pack what MispQLLanguagePack builds for this user
 * @var array $history MispQLHistory entries
 */
$this->set('headerTitle', __('Query console'));
$this->set('headerBreadcrumb', [__('API'), 'MispQL']);
$this->set('headerActions', [
    [
        'url' => $baseurl . '/api/rest',
        'label' => __('REST Client'),
        'type' => 'navigate',
        'icon' => 'terminal',
    ],
]);

echo $this->element('genericElements/assetLoader', ['css' => ['mispql-console']]);

// Module imports carry no query string of their own, so each module's
// version goes through the import map.
$modules = ['client', 'console', 'results', 'snippets', 'suggest', 'tokens', 'util', 'writer'];
$imports = [];
foreach ($modules as $module) {
    $path = 'js/mispql/' . $module . '.mjs';
    $version = is_file(WWW_ROOT . $path) ? filemtime(WWW_ROOT . $path) : $queryVersion;
    $imports[$baseurl . '/' . $path] = $baseurl . '/' . $path . '?v=' . $version;
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
                                <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown" aria-expanded="false"><i class="fas fa-wand-magic-sparkles" aria-hidden="true"></i><?= __('Examples') ?></button>
                                <ul class="dropdown-menu dropdown-menu-end"></ul>
                            </div>
                            <button type="button" class="btn btn-sm btn-outline-secondary" id="wb-clear" title="<?= __('Clear the writer') ?>"><i class="fas fa-eraser" aria-hidden="true"></i><?= __('Clear') ?></button>
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
                        </div>
                    </div>
                </div>
            </div>

            <div class="card wb-result" id="wb-result" aria-live="polite"></div>
        </div>
    </div>
</div>
<script type="application/json" id="mispql-language-pack"><?= json_encode($pack, $jsonFlags) ?></script>
<script type="application/json" id="mispql-history"><?= json_encode($history, $jsonFlags) ?></script>
<script type="importmap"><?= json_encode(['imports' => $imports], $jsonFlags) ?></script>
<script type="module" src="<?= h($entry) ?>"></script>
