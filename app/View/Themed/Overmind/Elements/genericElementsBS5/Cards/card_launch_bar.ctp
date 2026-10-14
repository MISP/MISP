<?php
/**
 * The action card of a detail view: a publication control, a grid of icon
 * tiles for the frequent actions, and a filterable menu holding every action.
 *
 * Action params:
 * - 'url' => string
 * - 'icon' => string
 * - 'label' => string
 * - 'short' => string    tile label (falls back to 'label')
 * - 'success' / 'warning' / 'danger' => bool (optional) tone; danger actions
 *                        only appear in the menu
 * - 'onclick' => string (optional)
 * - 'tour' => string (optional) data-tour anchor for the onboarding tour
 * - 'type' => 'post' (optional) renders a postLink, with 'confirm' and 'id'
 * - 'attributes' => array (optional) more attributes of the link
 * - 'primary' => bool    the state-changing action, drawn in the status bar
 * - 'pinned' => bool     shown as a tile
 * - 'entity' => string   tints the icon well: event, attribute, object, ...
 * - 'add' => bool        marks the tile with a "+" badge
 * - 'tileOrder' => int   position among the tiles (default: menu order)
 *
 * Separator params:
 * - 'divider' => true    starts a menu group
 * - 'label' => string    the group heading (optional)
 *
 * Card params:
 * - 'status' => ['published' => bool, 'readOnly' => bool,
 *                'pending' => bool, 'lastPublished' => int] (optional);
 *                pending marks a published event with changes made since
 * - 'maxTiles' => int    with this many actions or fewer, and nothing
 *                        destructive, every action is a tile and the menu is
 *                        dropped (default 8)
 * - 'columns' => int     tiles per row (default 4)
 * - 'autoPin' => bool    when no action is pinned, every non-destructive
 *                        action is a tile (default true)
 */

App::uses('CakeTime', 'Utility');

$actions = $actions ?? [];
$maxTiles = $maxTiles ?? 8;
$columns = $columns ?? 4;
$autoPin = $autoPin ?? true;

$groups = [];
$current = null;
$primary = null;
$danger = [];
foreach ($actions as $action) {
    if (!empty($action['divider'])) {
        $current = $action['label'] ?? '';
        continue;
    }
    if (!empty($action['primary']) && $primary === null) {
        $primary = $action;
    }
    if (!empty($action['danger'])) {
        $danger[] = $action;
        continue;
    }
    $groups[$current ?? ''][] = $action;
}

$candidates = [];
foreach ($groups as $groupActions) {
    foreach ($groupActions as $action) {
        if ($action !== $primary) {
            $candidates[] = $action;
        }
    }
}
$hasMenu = count($candidates) > $maxTiles || !empty($danger);
$pinned = array_values(array_filter($candidates, function ($a) {
    return !empty($a['pinned']);
}));
$tiles = $hasMenu && (!empty($pinned) || !$autoPin) ? $pinned : $candidates;
$tilePosition = function ($index) use ($tiles) {
    return [$tiles[$index]['tileOrder'] ?? PHP_INT_MAX, $index];
};
$order = array_keys($tiles);
usort($order, function ($a, $b) use ($tilePosition) {
    return $tilePosition($a) <=> $tilePosition($b);
});
$tiles = array_slice(array_map(function ($index) use ($tiles) {
    return $tiles[$index];
}, $order), 0, $hasMenu ? $maxTiles : count($tiles));
$total = count($candidates) + count($danger) + ($primary === null ? 0 : 1);

$tone = function (array $action) {
    if (!empty($action['danger'])) {
        return 'danger';
    }
    if (!empty($action['warning'])) {
        return 'warning';
    }
    if (!empty($action['success'])) {
        return 'success';
    }
    return $action['entity'] ?? 'neutral';
};

$link = function (array $action, $class, $inner, $withTour, array $extra = []) {
    $url = $action['url'] ?? '#';
    if (($action['type'] ?? null) === 'post') {
        $options = array_merge([
            'escape' => false,
            'class' => $class,
            'confirm' => $action['confirm'] ?? null,
        ], $extra);
        if (!empty($action['id'])) {
            $options['data'] = ['id' => $action['id']];
        }
        if ($withTour && !empty($action['tour'])) {
            $options['data-tour'] = $action['tour'];
        }
        return $this->Form->postLink($inner, $url, $options);
    }
    $attrs = ['class' => $class, 'href' => $url];
    if (!empty($action['onclick'])) {
        $attrs['onclick'] = $action['onclick'];
    }
    if ($withTour && !empty($action['tour'])) {
        $attrs['data-tour'] = $action['tour'];
    }
    $attrs = array_merge($attrs, $action['attributes'] ?? [], $extra);
    $html = '';
    foreach ($attrs as $name => $value) {
        $html .= sprintf(' %s="%s"', h($name), h($value));
    }
    return '<a' . $html . '>' . $inner . '</a>';
};

$well = function (array $action, $badge = false) use ($tone) {
    return sprintf(
        '<span class="lb-well lb-e-%s" aria-hidden="true"><i class="%s"></i>%s</span>',
        h($tone($action)),
        h($action['icon'] ?? 'fas fa-circle'),
        $badge && !empty($action['add'])
            ? '<span class="lb-plus"><i class="fas fa-plus"></i></span>'
            : ''
    );
};

// A tour anchor goes on the menu copy only when no tile or status button carries it.
$menuItem = function (array $action, $class = '') use ($link, $well, $tiles, $primary) {
    $label = $action['label'] ?? '';
    return $link(
        $action,
        trim('lb-item ' . $class),
        $well($action) . '<span class="lb-lbl">' . h($label) . '</span>'
            . ($class === 'lb-del' ? '<span class="lb-del-hint">' . __('permanent') . '</span>' : ''),
        $action !== $primary && !in_array($action, $tiles, true),
        ['role' => 'option', 'tabindex' => '-1', 'data-label' => $label]
    );
};

$published = !empty($status['published']);
$pending = !empty($status['pending']) && !empty($status['lastPublished']);
$publishedAt = $published && !$pending ? (int)($status['lastPublished'] ?? 0) : 0;
$statusClass = $pending ? 'is-pending' : ($published ? 'is-pub' : 'is-draft');
$statusTitle = '';
if ($pending) {
    $statusTitle = __('Published %s; changes made since then are not published yet', date('Y-m-d H:i:s', (int)$status['lastPublished']));
} elseif ($publishedAt > 0) {
    $statusTitle = __('Published %s', date('Y-m-d H:i:s', $publishedAt));
}
$ago = function ($stamp) {
    return CakeTime::timeAgoInWords($stamp, ['end' => '+100 years', 'accuracy' => ['year' => 'year', 'month' => 'month', 'week' => 'week', 'day' => 'day']]);
};
?>
<div class="card shadow-sm mb-3 lb-card" data-tour="quick-actions" data-launch-bar>
    <?php if (!empty($status) || $primary !== null): ?>
        <div class="lb-seg<?= $primary === null ? ' is-solo' : '' ?>" role="group" aria-label="<?= __('Publication') ?>">
            <span class="lb-status <?= $statusClass ?>"<?= $statusTitle !== '' ? ' title="' . h($statusTitle) . '"' : '' ?>>
                <span class="lb-dot" aria-hidden="true"></span>
                <?php if ($pending): ?>
                    <span class="lb-status-txt lb-status-stack">
                        <span><?= __('Changes pending') ?></span>
                        <span class="lb-status-sub"><?= h(__('Published %s', $ago($status['lastPublished']))) ?></span>
                    </span>
                <?php elseif ($publishedAt > 0): ?>
                    <span class="lb-status-txt lb-status-stack">
                        <span><?= __('Published') ?></span>
                        <span class="lb-status-sub"><?= h($ago($publishedAt)) ?></span>
                    </span>
                <?php else: ?>
                    <span class="lb-status-txt"><?= $published ? __('Published') : __('Unpublished') ?></span>
                <?php endif; ?>
                <?php if (!empty($status['readOnly'])): ?>
                    <span class="lb-ro"><?= __('view only') ?></span>
                <?php endif; ?>
            </span>
            <?php if ($primary !== null): ?>
                <?= $link(
                    $primary,
                    'lb-pri ' . (!empty($primary['warning']) ? 'is-undo' : 'is-go'),
                    '<i class="' . h($primary['icon'] ?? '') . '" aria-hidden="true"></i>'
                        . '<span>' . h($primary['short'] ?? $primary['label'] ?? '') . '</span>',
                    true,
                    ['title' => $primary['label'] ?? '']
                ) ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($tiles)): ?>
        <div class="lb-grid<?= $columns > 4 ? ' is-dense' : '' ?>"<?= $columns === 4 ? '' : ' style="--lb-cols: ' . (int)$columns . '"' ?>>
            <?php foreach ($tiles as $action): ?>
                <?= $link(
                    $action,
                    'lb-tile',
                    $well($action, true)
                        . '<span class="lb-tile-lbl">' . h($action['short'] ?? $action['label'] ?? '') . '</span>',
                    true,
                    ['title' => $action['label'] ?? '', 'aria-label' => $action['label'] ?? '']
                ) ?>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($total === 0 && empty($status)): ?>
        <p class="text-muted mb-0 small px-1"><?= __('No action available') ?></p>
    <?php endif; ?>

    <?php if ($hasMenu): ?>
        <div class="lb-cmd">
            <div class="lb-field">
                <span class="lb-bolt" aria-hidden="true"><i class="fas fa-bolt"></i></span>
                <input type="text" class="lb-input" role="combobox" autocomplete="off" spellcheck="false"
                       aria-expanded="false" aria-autocomplete="list"
                       aria-label="<?= __('All actions, type to filter') ?>"
                       placeholder="<?= __('All actions — type to filter') ?>">
                <span class="lb-count" aria-hidden="true"><?= $total ?></span>
                <button type="button" class="lb-tog" tabindex="-1" aria-label="<?= __('Show all actions') ?>">
                    <i class="fas fa-chevron-down"></i>
                </button>
            </div>
            <div class="lb-menu" hidden>
                <div class="lb-list" role="listbox" aria-label="<?= __('Actions') ?>">
                    <?php foreach ($groups as $label => $groupActions): ?>
                        <div class="lb-grp">
                            <?php if ($label !== ''): ?>
                                <div class="lb-grp-h" aria-hidden="true"><?= h($label) ?></div>
                            <?php endif; ?>
                            <?php foreach ($groupActions as $action): ?>
                                <?= $menuItem($action) ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                    <?php if (!empty($danger)): ?>
                        <div class="lb-grp lb-grp-danger">
                            <?php foreach ($danger as $action): ?>
                                <?= $menuItem($action, 'lb-del') ?>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <div class="lb-empty" hidden><?= __('No action matches') ?> “<span></span>”</div>
                </div>
                <div class="lb-foot" aria-hidden="true">
                    <span><kbd>↑</kbd><kbd>↓</kbd> <?= __('move') ?></span>
                    <span><kbd>↵</kbd> <?= __('run') ?></span>
                    <span><kbd>esc</kbd> <?= __('close') ?></span>
                </div>
            </div>
        </div>
    <?php endif; ?>
</div>
<?php
echo $this->element('genericElements/assetLoader', [
    'css' => ['launch-bar'],
    'js' => ['launch-bar'],
]);
