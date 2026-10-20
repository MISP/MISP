<?php
/**
 * The chrome every side panel shares (side-panel.js): the resize grip and the
 * window edges, a head with the title, the panel's own tools and the undock,
 * widen and close buttons, and a body the panel's script fills.
 *
 * Required params:
 *   $id     string  the aside's id, which its navbar button names
 *   $title  string
 *   $icon   string  full class attribute of the glyph before the title
 *
 * Optional params:
 *   $shortcut  string  the key that shows or hides it, for the hints
 *   $tools     string  raw HTML of the head's own tools, before undock and
 *                      widen; escape it yourself
 *   $subhead   string  raw HTML between the head and the body, which reloads
 *                      of the body leave alone; escape it yourself
 *   $attrs     array   more attributes on the aside, e.g. data-url
 *   $text      array   strings for the panel's script, next to the shared ones
 *   $closeLabel string
 */
$attributes = '';
foreach ($attrs ?? [] as $name => $value) {
    $attributes .= sprintf(' %s="%s"', h($name), h($value));
}
$text = array_merge([
    'shortcut' => empty($shortcut) ? '' : __('%s shows or hides it', $shortcut),
    'widen' => __('Widen the panel'),
    'narrow' => __('Back to your width'),
    'undocked' => __('Undocked into a window.'),
    'docked' => __('Docked to the right.'),
    'failed' => __('Failed to load.'),
    'retry' => __('Try again'),
    'saveFailed' => __('It could not be saved.'),
], $text ?? []);
?>
<aside id="<?= h($id) ?>" class="sp-panel" role="region" aria-labelledby="<?= h($id) ?>-title" hidden<?= $attributes ?>>
    <div class="sp-grip" role="separator" tabindex="0" aria-orientation="vertical" aria-controls="<?= h($id) ?>"
         aria-label="<?= __('Panel width') ?>" title="<?= __('Drag to resize · double-click to widen') ?>" data-sp-grip>
        <span class="sp-grip-knob" aria-hidden="true"></span>
    </div>
    <?php foreach (['n', 's', 'e', 'w', 'nw', 'ne', 'sw'] as $edge): ?>
        <div class="sp-edge" data-sp-edge="<?= $edge ?>" hidden aria-hidden="true"></div>
    <?php endforeach; ?>
    <div class="sp-edge" data-sp-edge="se" hidden tabindex="0" role="button"
         aria-label="<?= __('Resize the window (arrow keys)') ?>" title="<?= __('Drag to resize') ?>"></div>
    <header class="sp-head">
        <button type="button" class="sp-tool sp-move" data-sp-move hidden
                title="<?= __('Drag to move · arrow keys') ?>" aria-label="<?= __('Move the window (arrow keys)') ?>">
            <i class="fas fa-grip-vertical" aria-hidden="true"></i>
        </button>
        <i class="<?= h($icon) ?> sp-icon" aria-hidden="true"></i>
        <h2 id="<?= h($id) ?>-title" class="sp-title"><?= h($title) ?></h2>
        <div class="sp-tools">
            <?= $tools ?? '' ?>
            <button type="button" class="sp-tool" data-sp-undock title="<?= __('Undock into a window') ?>" aria-label="<?= __('Undock into a window') ?>">
                <i class="fas fa-window-restore" aria-hidden="true"></i>
            </button>
            <button type="button" class="sp-tool" data-sp-dock hidden title="<?= __('Dock to the right') ?>" aria-label="<?= __('Dock to the right') ?>">
                <i class="fas fa-table-columns" aria-hidden="true"></i>
            </button>
            <button type="button" class="sp-tool" data-sp-widen aria-pressed="false" title="<?= __('Widen the panel') ?>" aria-label="<?= __('Widen the panel') ?>">
                <i class="fas fa-left-right" aria-hidden="true"></i>
            </button>
            <button type="button" class="btn-close sp-close" data-sp-close
                    aria-label="<?= h($closeLabel ?? __('Close the panel')) ?>" title="<?= __('Close (Esc)') ?>"></button>
        </div>
    </header>
    <?php if (!empty($subhead)): ?>
        <div class="sp-subhead"><?= $subhead ?></div>
    <?php endif; ?>
    <div class="sp-body" data-sp-body>
        <div class="sp-loading" role="status">
            <div class="misp-loader" aria-hidden="true"></div>
            <div><?= __('Loading') ?></div>
        </div>
    </div>
    <div class="visually-hidden" aria-live="polite" data-sp-say></div>
    <script type="application/json" data-sp-text><?= json_encode($text, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
</aside>
