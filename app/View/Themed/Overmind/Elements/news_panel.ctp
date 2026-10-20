<?php
/**
 * The news panel, opened by the navbar's News button or N. news-panel.js loads
 * News/ajax/panel.ctp into it on open, and markdown-it with it, so neither
 * weighs on a page where it stays shut.
 */
$markdownUrl = $this->Html->assetUrl('markdown-it', [
    'pathPrefix' => Configure::read('App.jsBaseUrl'),
    'ext' => '.js',
]);
$markdownVersion = Configure::read('Asset.timestamp') === 'cached' && file_exists(WWW_ROOT . $markdownUrl)
    ? filemtime(WWW_ROOT . $markdownUrl)
    : null;
$markdownUrl .= '?v=' . ($markdownVersion ?: $queryVersion);

$tools = '';
if ($this->Acl->canAccess('news', 'add')) {
    $tools = sprintf(
        '<button type="button" class="sp-tool" data-sp-modal="%s" title="%s" aria-label="%s"><i class="fas fa-plus" aria-hidden="true"></i></button>',
        h($baseurl . '/news/add'),
        h(__('Add news item')),
        h(__('Add news item'))
    );
}

echo $this->element('side_panel', [
    'id' => 'nw-so',
    'title' => __('News'),
    'icon' => 'fas fa-newspaper',
    'shortcut' => 'N',
    'tools' => $tools,
    'closeLabel' => __('Close the news panel'),
    'attrs' => [
        'data-url' => $baseurl . '/news/index',
        'data-markdown' => $markdownUrl,
    ],
    'text' => [
        'failed' => __('Failed to load the news.'),
        'olderFailed' => __('Failed to load older news.'),
        'added' => __('News item added.'),
        'saved' => __('News item saved.'),
        'deleted' => __('News item deleted.'),
        'saveFailed' => __('The news item could not be saved.'),
    ],
]);
echo $this->element('genericElements/assetLoader', ['js' => ['news-panel']]);
