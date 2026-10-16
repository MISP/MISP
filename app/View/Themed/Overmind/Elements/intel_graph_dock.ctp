<?php
/**
 * The analyst graph dock, opened by the navbar's graph slot. Hidden until
 * then; intel-graph-dock.js fills it and mounts the graph on first open.
 */
?>
<aside id="ig-so" class="ig-so" role="region" aria-labelledby="ig-so-label ig-so-name" hidden>
    <div class="ig-so-grip" role="separator" tabindex="0" aria-orientation="vertical" aria-controls="ig-so"
         aria-label="<?= __('Graph panel width') ?>" title="<?= __('Drag to resize · double-click to widen') ?>" data-ig-grip>
        <span class="ig-so-grip-knob" aria-hidden="true"></span>
    </div>
    <?php foreach (['n', 's', 'e', 'w', 'nw', 'ne', 'sw'] as $edge): ?>
        <div class="ig-fw-edge" data-ig-edge="<?= $edge ?>" hidden aria-hidden="true"></div>
    <?php endforeach; ?>
    <div class="ig-fw-edge" data-ig-edge="se" hidden tabindex="0" role="button"
         aria-label="<?= __('Resize the window (arrow keys)') ?>" title="<?= __('Drag to resize') ?>"></div>
    <header class="ig-so-head">
        <div class="ig-so-top">
            <button type="button" class="ig-so-tool ig-so-move" data-ig-move hidden
                    title="<?= __('Drag to move · arrow keys') ?>" aria-label="<?= __('Move the window (arrow keys)') ?>">
                <i class="fas fa-grip-vertical" aria-hidden="true"></i>
            </button>
            <span id="ig-so-label" class="visually-hidden"><?= __('Analyst graph:') ?></span>
            <div class="dropdown ig-so-switch">
                <button type="button" class="ig-so-title" data-ig-switch data-bs-toggle="dropdown"
                        data-bs-auto-close="outside" aria-expanded="false" title="<?= __('Switch graph') ?>">
                    <i class="misp-icon misp-icon-analyst-graph misp-simple ig-so-title-icon" aria-hidden="true"></i>
                    <span id="ig-so-name" class="ig-so-name" data-ig-name><?= __('Analyst graph') ?></span>
                    <i class="fas fa-chevron-down ig-so-caret" aria-hidden="true"></i>
                </button>
                <div class="dropdown-menu ig-so-menu" data-ig-menu></div>
            </div>
            <div class="ig-so-tools">
                <button type="button" class="ig-so-tool" data-ig-undock title="<?= __('Undock into a window') ?>" aria-label="<?= __('Undock into a window') ?>">
                    <i class="fas fa-window-restore" aria-hidden="true"></i>
                </button>
                <button type="button" class="ig-so-tool" data-ig-dock hidden title="<?= __('Dock to the right') ?>" aria-label="<?= __('Dock to the right') ?>">
                    <i class="fas fa-table-columns" aria-hidden="true"></i>
                </button>
                <button type="button" class="ig-so-tool" data-ig-widen aria-pressed="false" title="<?= __('Widen the panel') ?>" aria-label="<?= __('Widen the panel') ?>">
                    <i class="fas fa-left-right" aria-hidden="true"></i>
                </button>
                <a class="ig-so-tool" data-ig-full href="#" title="<?= __('Open full page') ?>" aria-label="<?= __('Open full page') ?>">
                    <i class="fas fa-up-right-from-square" aria-hidden="true"></i>
                </a>
                <button type="button" class="btn-close ig-so-close" data-ig-close aria-label="<?= __('Close the graph panel') ?>" title="<?= __('Close (Esc)') ?>"></button>
            </div>
        </div>
        <div class="ig-so-meta" data-ig-meta></div>
        <div class="ig-so-banner" data-ig-banner hidden></div>
    </header>
    <div class="ig-so-stage" data-ig-stage>
        <div class="ig-so-canvas" data-ig-canvas></div>
        <div class="ig-so-callouts" data-ig-callouts aria-hidden="true"></div>
        <div class="ig-so-loading" data-ig-loading hidden role="status">
            <div class="misp-loader" aria-hidden="true"></div>
            <div data-ig-loading-text><?= __('Loading') ?></div>
            <div class="ig-so-skeleton" aria-hidden="true"><span></span><span></span><span></span></div>
        </div>
        <div class="ig-so-none" data-ig-none hidden></div>
    </div>
    <section class="ig-so-tray" data-ig-tray aria-labelledby="ig-so-tray-label" hidden>
        <div class="ig-so-tray-bar">
            <button type="button" class="ig-so-tray-head" data-ig-tray-toggle aria-expanded="true" aria-controls="ig-so-tray-list">
                <span id="ig-so-tray-label"><?= __('Arrivals') ?></span>
                <span data-ig-tray-new></span>
                <i class="fas fa-chevron-down ig-so-caret" aria-hidden="true"></i>
            </button>
            <button type="button" class="ig-so-tool ig-so-tray-clear" data-ig-tray-clear hidden
                    title="<?= __('Clear the arrivals') ?>" aria-label="<?= __('Clear the arrivals') ?>">
                <i class="fas fa-broom" aria-hidden="true"></i>
            </button>
        </div>
        <ol id="ig-so-tray-list" class="ig-so-tray-list" data-ig-tray-list></ol>
    </section>
    <footer class="ig-so-foot" data-ig-foot hidden></footer>
    <div class="visually-hidden" aria-live="polite" data-ig-say></div>
</aside>
