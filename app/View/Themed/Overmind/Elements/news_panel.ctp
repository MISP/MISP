<?php
/**
 * The news panel, opened by the navbar's News button or N. Hidden until then;
 * news-panel.js loads News/ajax/panel.ctp into it on open, and markdown-it
 * with it, so neither weighs on a page where it stays shut.
 *
 * @var array $newsPanel `unread`: news the user has not read yet
 */
$markdownUrl = $this->Html->assetUrl('markdown-it', [
    'pathPrefix' => Configure::read('App.jsBaseUrl'),
    'ext' => '.js',
]);
$markdownVersion = Configure::read('Asset.timestamp') === 'cached' && file_exists(WWW_ROOT . $markdownUrl)
    ? filemtime(WWW_ROOT . $markdownUrl)
    : null;
$markdownUrl .= '?v=' . ($markdownVersion ?: $queryVersion);
?>
<aside id="nw-so" class="nw-so" role="region" aria-labelledby="nw-so-title" hidden
       data-url="<?= h($baseurl . '/news/index') ?>" data-markdown="<?= h($markdownUrl) ?>">
    <div class="nw-so-grip" role="separator" tabindex="0" aria-orientation="vertical" aria-controls="nw-so"
         aria-label="<?= __('News panel width') ?>" title="<?= __('Drag to resize · double-click to widen') ?>" data-news-grip>
        <span class="nw-so-grip-knob" aria-hidden="true"></span>
    </div>
    <?php foreach (['n', 's', 'e', 'w', 'nw', 'ne', 'sw'] as $edge): ?>
        <div class="nw-fw-edge" data-news-edge="<?= $edge ?>" hidden aria-hidden="true"></div>
    <?php endforeach; ?>
    <div class="nw-fw-edge" data-news-edge="se" hidden tabindex="0" role="button"
         aria-label="<?= __('Resize the window (arrow keys)') ?>" title="<?= __('Drag to resize') ?>"></div>
    <header class="nw-so-head">
        <button type="button" class="nw-so-tool nw-so-move" data-news-move hidden
                title="<?= __('Drag to move · arrow keys') ?>" aria-label="<?= __('Move the window (arrow keys)') ?>">
            <i class="fas fa-grip-vertical" aria-hidden="true"></i>
        </button>
        <i class="fas fa-newspaper nw-so-icon" aria-hidden="true"></i>
        <h2 id="nw-so-title" class="nw-so-title"><?= __('News') ?></h2>
        <div class="nw-so-tools">
            <?php if ($this->Acl->canAccess('news', 'add')): ?>
                <button type="button" class="nw-so-tool" data-news-modal="<?= h($baseurl . '/news/add') ?>"
                        title="<?= __('Add news item') ?>" aria-label="<?= __('Add news item') ?>">
                    <i class="fas fa-plus" aria-hidden="true"></i>
                </button>
            <?php endif; ?>
            <button type="button" class="nw-so-tool" data-news-undock title="<?= __('Undock into a window') ?>" aria-label="<?= __('Undock into a window') ?>">
                <i class="fas fa-window-restore" aria-hidden="true"></i>
            </button>
            <button type="button" class="nw-so-tool" data-news-dock hidden title="<?= __('Dock to the right') ?>" aria-label="<?= __('Dock to the right') ?>">
                <i class="fas fa-table-columns" aria-hidden="true"></i>
            </button>
            <button type="button" class="nw-so-tool" data-news-widen aria-pressed="false" title="<?= __('Widen the panel') ?>" aria-label="<?= __('Widen the panel') ?>">
                <i class="fas fa-left-right" aria-hidden="true"></i>
            </button>
            <button type="button" class="btn-close nw-so-close" data-news-close
                    aria-label="<?= __('Close the news panel') ?>" title="<?= __('Close (Esc)') ?>"></button>
        </div>
    </header>
    <div class="nw-so-body" data-news-body>
        <div class="nw-so-loading" role="status">
            <div class="misp-loader" aria-hidden="true"></div>
            <div><?= __('Loading') ?></div>
        </div>
    </div>
    <div class="visually-hidden" aria-live="polite" data-news-say></div>
    <script type="application/json" data-news-text><?= json_encode([
        'failed' => __('Failed to load the news.'),
        'retry' => __('Try again'),
        'olderFailed' => __('Failed to load older news.'),
        'shortcut' => __('N shows or hides it'),
        'widen' => __('Widen the panel'),
        'narrow' => __('Back to your width'),
        'undocked' => __('Undocked into a window.'),
        'docked' => __('Docked to the right.'),
        'added' => __('News item added.'),
        'saved' => __('News item saved.'),
        'deleted' => __('News item deleted.'),
        'saveFailed' => __('The news item could not be saved.'),
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
</aside>
<?= $this->element('genericElements/assetLoader', ['js' => ['news-panel']]) ?>
