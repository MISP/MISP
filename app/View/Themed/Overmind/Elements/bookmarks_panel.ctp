<?php
/**
 * The bookmarks panel, opened by the navbar's Bookmarks button or B.
 * bookmarks-panel.js loads Bookmarks/ajax/panel.ctp into it on open.
 */
$subhead = sprintf(
    '<div class="bm-here">'
        . '<button type="button" class="btn btn-sm btn-primary" data-bm-add><i class="fas fa-star me-1" aria-hidden="true"></i>%s</button>'
        . '<button type="button" class="btn btn-sm btn-outline-primary set-homepage"><i class="fas fa-house me-1" aria-hidden="true"></i>%s</button>'
    . '</div>'
    . '<div class="bm-filter" data-bm-filter-box>'
        . '<i class="fas fa-magnifying-glass" aria-hidden="true"></i>'
        . '<input type="search" class="form-control form-control-sm" data-bm-filter placeholder="%s" aria-label="%s" autocomplete="off">'
        . '<span class="bm-filter-count" data-bm-count aria-live="polite" hidden></span>'
    . '</div>',
    h(__('Bookmark this page')),
    h(__('Set as homepage')),
    h(__('Search bookmarks')),
    h(__('Search bookmarks'))
);

echo $this->element('side_panel', [
    'id' => 'bm-so',
    'title' => __('Bookmarks'),
    'icon' => 'fas fa-star',
    'shortcut' => 'B',
    'subhead' => $subhead,
    'closeLabel' => __('Close the bookmarks panel'),
    'attrs' => [
        'data-url' => $baseurl . '/bookmarks/panel',
        'data-add' => $baseurl . '/bookmarks/add',
    ],
    'text' => [
        'failed' => __('Failed to load the bookmarks.'),
        'added' => __('Bookmark added.'),
        'saved' => __('Bookmark saved.'),
        'deleted' => __('Bookmark deleted.'),
        'saveFailed' => __('The bookmark could not be saved.'),
    ],
]);
echo $this->element('genericElements/assetLoader', ['js' => ['bookmarks-panel']]);
