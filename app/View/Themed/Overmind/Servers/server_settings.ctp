<?php
/**
 * Server settings: a navigation on the left, the selected destination on the
 * right. The content is fetched over ajax from this same action
 * (ServersController::serverSettings), on the first load as on every click
 * of the navigation, so a page keeps the URL of the destination it shows.
 */

App::uses('ServerHealthProbes', 'Tools');

$this->set('headerTitle', __('Server Settings & Maintenance'));
$this->set('headerDescription', __('Review and tune the configuration of this instance.'));
$this->set('headerCountText', '');
$this->set('headerActions', array(
    array(
        'type' => 'navigate',
        'url' => $baseurl . '/servers/serverSettings/download',
        'icon' => 'download',
        'label' => __('Download report'),
    ),
));

echo $this->element('genericElements/assetLoader', array('js' => array('server-settings')));

$config = array(
    'base' => $baseurl . '/servers/serverSettings',
    'diagnosticBase' => $baseurl . '/servers/serverDiagnostic',
    'destination' => $destination,
    'staleAfter' => ServerHealthProbes::STALE_AFTER,
    'verdicts' => (object)$healthVerdicts,
    'probes' => ServerHealthProbes::probes(),
    'labels' => array(
        'loadFailed' => __('This page could not be loaded.'),
        'retry' => __('Retry'),
        'probeFailed' => __('The check could not be run.'),
        'checking' => __('Checking…'),
        'checkedNow' => __('checked just now'),
        'checkedMinutes' => __('checked %s min ago'),
        'checkedHours' => __('checked %s h ago'),
        'checkedDays' => __('checked %s d ago'),
        'notChecked' => __('not checked yet'),
        'healthProgress' => __('%s of %s checks done'),
        'healthDone' => __('Every check is done. Open a tile for its details.'),
        'formFailed' => __('Could not load the edit form.'),
        'saveFailed' => __('The setting could not be saved.'),
        'saved' => __('Setting updated.'),
        'refreshFailed' => __('The setting was saved but the row could not be refreshed.'),
        'searchEmpty' => __('No setting matches.'),
        'searchHint' => __('Type to search the name and description of every setting, advanced and deprecated ones included.'),
        'searchLoading' => __('Loading the settings…'),
        'searchMore' => __('%s more results, refine the search to see them.'),
        'tiers' => array(
            'essential' => __('Essential'),
            'standard' => __('Standard'),
            'advanced' => __('Advanced'),
            'deprecated' => __('Deprecated'),
        ),
        'inError' => __('to fix'),
        'filterSearch' => __('Search'),
        'onlyProblems' => __('Only problems'),
        'onlyModified' => __('Only modified'),
        'showAdvanced' => __('Advanced settings shown'),
        'cancel' => __('Cancel'),
        'ok' => __('OK'),
        'recommended' => __('removal recommended'),
        'badLinks' => __('bad links detected'),
        'checkFailed' => __('The check could not be run.'),
        'zmqFailed' => __('The ZeroMQ action failed.'),
        'jsonLoaded' => __('JSON files loaded into the database.'),
        'jsonFailed' => __('Could not load the JSON files.'),
        'submodulesFailed' => __('Could not load the submodule status.'),
    ),
);
?>

<?php if (!$configWriteable): ?>
    <div class="container-fluid">
        <div class="alert alert-danger d-flex align-items-center gap-2" role="alert">
            <i class="fas fa-triangle-exclamation"></i>
            <?= __('Warning: app/Config/config.php is not writeable. This means that any setting changes made here will NOT be saved.') ?>
        </div>
    </div>
<?php endif; ?>

<div class="container-fluid ss-scope ss-shell" id="ssShell">
    <div class="ss-layout">
        <div class="ss-layout-nav">
            <div class="ss-nav-sticky">
                <?= $this->element('healthElementsBS5/settings_nav') ?>
            </div>
        </div>
        <div class="ss-layout-main">
            <div id="ssContent" class="ss-content" aria-live="polite">
                <div class="d-flex flex-column gap-3" aria-hidden="true">
                    <span class="ss-skeleton" style="width: 40%; height: 1.6rem;"></span>
                    <span class="ss-skeleton" style="width: 100%; height: 8rem;"></span>
                    <span class="ss-skeleton" style="width: 100%; height: 14rem;"></span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="ssSearchModal" tabindex="-1" aria-labelledby="ssSearchLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable ss-search-dialog">
        <div class="modal-content">
            <div class="modal-header gap-2">
                <i class="fas fa-magnifying-glass text-muted"></i>
                <label for="ssSearchInput" class="visually-hidden" id="ssSearchLabel"><?= __('Search all settings') ?></label>
                <input type="search" class="form-control border-0 shadow-none ss-search-input" id="ssSearchInput"
                       autocomplete="off" placeholder="<?= h(__('Search all settings')) ?>">
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= h(__('Close')) ?>"></button>
            </div>
            <div class="modal-body p-2" id="ssSearchResults" role="listbox" aria-label="<?= h(__('Results')) ?>"></div>
            <div class="modal-footer justify-content-between small text-muted py-2">
                <span><kbd>↑</kbd> <kbd>↓</kbd> <?= __('to move') ?> · <kbd>Enter</kbd> <?= __('to open') ?></span>
                <span><?= __('Advanced and deprecated settings included') ?></span>
            </div>
        </div>
    </div>
</div>

<script type="application/json" id="ssConfig"><?= json_encode($config, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
