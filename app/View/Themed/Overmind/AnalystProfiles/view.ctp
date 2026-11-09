<?php
/**
 * A profile on the frame of the server settings page: the list of its
 * sections, a search over every parameter, and each parameter edited
 * where it is shown (analyst-profile-settings.js). The writes are in the
 * header; whom the profile scores and its facts are behind About.
 *
 * @var array $profile
 * @var array $bench
 * @var bool $may_edit
 * @var array|null $standing This profile's row of the index board
 */
App::uses('ProfileActionsTool', 'Tools/AnalystProfile');

echo $this->element('genericElements/assetLoader', array(
    'css' => array('value-palette', 'analyst-profile', 'index-filters'),
    'js' => array('analyst-profile', 'analyst-profile-help',
        'analyst-profile-settings'),
));
echo $this->element('AnalystProfiles/profile_header');

/*
 * One entry per action, typed by what it does; headerSection folds the
 * actions of one type into a single split button. The writes all ask
 * first in #mainModal. About is a modal too but read only, so it keeps a
 * button of its own beside that group; comparing a value is done from the
 * try bar, under the value it compares.
 */
$headerActions = array(
    array(
        'type' => 'navigate',
        'label' => __('Export JSON'),
        'icon' => 'file-export',
        'url' => $this->Html->url(array('action' => 'export', $profile['id'])),
    ),
    array(
        'type' => 'modal',
        'label' => __('About'),
        'icon' => 'circle-info',
        'url' => $this->Html->url(array('action' => 'view', $profile['id'],
            '?' => array('fragment' => 'about'))),
        'size' => 'lg',
        'class' => 'btn btn-outline-primary',
        'standalone' => true,
    ),
);
if ($standing !== null) {
    $writes = ProfileActionsTool::writes($standing, array(
        'org' => !empty($me['Role']['perm_admin']),
        'instance' => !empty($me['Role']['perm_site_admin']),
        'fork_org' => !empty($me['Role']['perm_admin'])
            || !empty($me['Role']['perm_site_admin']),
    ));
    // The button the group keeps: using the profile, or forking one you cannot use.
    $hasPrimary = false;
    foreach (array('use', 'fork', 'share', 'delete') as $kind) {
        foreach ($writes[$kind] as $write) {
            if ($write['disabled']) {
                continue;
            }
            $action = array(
                'type' => 'modal',
                'label' => $write['label'],
                'icon' => $write['icon'],
                'url' => $this->Html->url($write['url']),
                'size' => 'md',
            );
            if ($kind === 'delete') {
                $action['class'] = 'text-danger';
            } elseif (!$hasPrimary && $kind !== 'share') {
                $hasPrimary = true;
                $action['primary'] = true;
            }
            $headerActions[] = $action;
        }
    }
}

$this->set('headerActions', $headerActions);

$config = array(
    'editUrl' => $this->Html->url(array('action' => 'edit', $profile['id'])),
    'viewUrl' => $this->Html->url(array('action' => 'view', $profile['id'])),
    'mayEdit' => (bool)$may_edit,
    'labels' => array(
        'save' => __('Save'),
        'cancel' => __('Cancel'),
        'discard' => __('Discard'),
        'unsaved' => __('Unsaved changes'),
        'edit' => __('Edit'),
        'editHint' => __('Click to change it'),
        'keys' => __('Enter saves, Esc cancels'),
        'saved' => __('Saved. Revision %s.'),
        'unchanged' => __('Nothing changed.'),
        'saveFailed' => __('The change could not be saved.'),
        'notSaved' => __('Not saved.'),
        'atLine' => __('Line %s.'),
        'formFailed' => __('The editor could not be loaded.'),
        'refreshFailed' => __('Saved, but the page could not be redrawn. Reload it.'),
        'searchHint' => __('Type to search the name, value and description of'
            . ' every parameter, in every section.'),
        'searchEmpty' => __('No parameter matches.'),
        'searchMore' => __('%s more results, refine the search to see them.'),
    ),
);
?>
<div class="container-fluid ss-scope ap-page ap-set" id="ap-board" data-ap-settings>
    <?= $this->element('AnalystProfiles/settings_board') ?>
</div>

<div class="modal fade" id="ssSearchModal" tabindex="-1" aria-labelledby="apSearchLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable ss-search-dialog">
        <div class="modal-content">
            <div class="modal-header gap-2">
                <i class="fas fa-magnifying-glass text-muted"></i>
                <label for="apSearchInput" class="visually-hidden" id="apSearchLabel"><?= h(__('Search all parameters')) ?></label>
                <input type="search" class="form-control border-0 shadow-none ss-search-input" id="apSearchInput"
                       autocomplete="off" placeholder="<?= h(__('Search all parameters')) ?>">
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= h(__('Close')) ?>"></button>
            </div>
            <div class="modal-body p-2" id="apSearchResults" role="listbox" aria-label="<?= h(__('Results')) ?>"></div>
            <div class="modal-footer justify-content-between small text-muted py-2">
                <span><kbd>↑</kbd> <kbd>↓</kbd> <?= h(__('to move')) ?> · <kbd>Enter</kbd> <?= h(__('to open')) ?></span>
                <span><?= h(__('Every section, folded parameters included')) ?></span>
            </div>
        </div>
    </div>
</div>

<script type="application/json" id="ap-settings-config"><?= json_encode($config,
    JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
