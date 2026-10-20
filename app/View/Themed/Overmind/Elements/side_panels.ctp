<?php
/**
 * The side panels a page's navbar opens (AppController::beforeRender sets
 * `sidePanels`), after side-panel.js, which each of them builds on.
 *
 * @var array $panels
 */
echo $this->element('genericElements/assetLoader', ['js' => ['side-panel']]);
if (!empty($panels['news'])) {
    echo $this->element('news_panel');
}
if (!empty($panels['bookmarks'])) {
    echo $this->element('bookmarks_panel');
}
