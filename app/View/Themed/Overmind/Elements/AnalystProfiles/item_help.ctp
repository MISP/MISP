<?php
/**
 * The body of a row's "How it works" popover, cloned out of a
 * `<template>` by analyst-profile-help.js. One element for signals,
 * conflict rules and exclusions: what differs between them is in the
 * view-model's `tags` and `lands`.
 *
 * @var array $help AnalystProfileFormTool::itemHelp()
 */
$values = $help['values'];

$token = function ($m) use ($values) {
    if (!isset($values[$m[1]])) {
        return $m[0];
    }
    $slot = $values[$m[1]];
    $value = $slot['value'] !== null ? $slot['value'] : $slot['fallback'];
    if (is_bool($value)) {
        $value = $value ? 'true' : 'false';
    }
    return '<b class="sig-pop-v" data-ap-help-for="' . h($slot['input']) . '"'
        . ($slot['fallback'] === null
            ? ''
            : ' data-ap-help-fallback="' . h((string)$slot['fallback']) . '"')
        . '>' . h($value === null ? '?' : (string)$value) . '</b>';
};
/*
 * Names a reader has to go and find (a row id, a setting) are set as
 * code. Notes and recipes also mark this row's own one-word keys, which
 * in the descriptive prose are as often plain words ("the last 90 days").
 */
$names = array('conflict:[a-z-]+', '[a-z_]{3,}\.[a-z_]{3,}',
    '[a-z0-9]+(?:_[a-z0-9]+)+');
$ownKeys = array_map(function ($key) {
    return preg_quote($key, '/');
}, array_keys($values));
$mark = function ($html, array $names) {
    return preg_replace('/(?<![\w{.:-])(' . implode('|', $names)
        . ')(?![\w}])/', '<code>$1</code>', $html);
};
$fill = function ($text, $withKeys = false) use ($token, $mark, $names,
    $ownKeys
) {
    $html = $mark(h($text),
        $withKeys ? array_merge($names, $ownKeys) : $names);
    return preg_replace_callback('/\{([a-z0-9_]+)\}/', $token, $html);
};

$tagClass = array(
    'pill' => 'pill t-missing',
    'tag' => 'sig-tag',
    'mult' => 'sig-tag is-mult',
);
$titleId = 'sig-pop-title-' . preg_replace('/[^a-z0-9_-]/i', '-', $help['id']);
?>
<div class="sig-pop-body" aria-labelledby="<?= h($titleId) ?>">
    <div class="sig-pop-head">
        <div class="sig-pop-titles">
            <p class="sig-pop-title" id="<?= h($titleId) ?>"><?=
                h($help['name']) ?></p>
            <p class="sig-pop-id"><?= h($help['id']) ?></p>
        </div>
        <button type="button" class="sig-pop-close" data-ap-help-close
                aria-label="<?= h(__('Close')) ?>">
            <i class="fa-solid fa-xmark" aria-hidden="true"></i>
        </button>
    </div>
    <?php if (!empty($help['tags'])): ?>
        <div class="sig-pop-tags">
            <?php foreach ($help['tags'] as $tag): ?>
                <span class="<?= h($tagClass[$tag['style']]) ?>"<?=
                    empty($tag['title'])
                        ? '' : ' title="' . h($tag['title']) . '"' ?>>
                    <?php if (!empty($tag['key'])): ?>
                        <span class="k"><?= h($tag['key']) ?></span>
                    <?php endif; ?>
                    <?= $tag['style'] === 'tag'
                        ? '<b>' . h($tag['label']) . '</b>'
                        : h($tag['label']) ?>
                </span>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
    <div class="sig-pop-grid<?= empty($help['settings']) ? ' no-b' : '' ?>">
        <div class="sig-pop-col" data-col="a">
            <?php if (!empty($help['what'])): ?>
                <h4><?= h(__('What it looks at')) ?></h4>
                <p><?= $fill($help['what']) ?></p>
            <?php endif; ?>
            <?php if (!empty($help['how'])): ?>
                <h4><?= h($help['how_title']) ?></h4>
                <p><?= $fill($help['how']) ?></p>
            <?php endif; ?>
            <?php if (!empty($help['lands'])): ?>
                <p class="sig-pop-lands"><?= h($help['lands']) ?></p>
            <?php endif; ?>
            <?php if (!empty($help['note'])): ?>
                <p class="sig-pop-note">
                    <i class="fa-solid fa-circle-info" aria-hidden="true"></i>
                    <span><?= $fill($help['note'], true) ?></span>
                </p>
            <?php endif; ?>
        </div>
        <?php if (!empty($help['settings'])): ?>
            <div class="sig-pop-col" data-col="b">
                <h4><?= h(__('Its settings')) ?></h4>
                <ul class="sig-pop-settings">
                    <?php foreach ($help['settings'] as $setting): ?>
                        <li><span class="kv"><k><?= h($setting['key']) ?></k><?=
                            $fill('{' . $setting['key'] . '}') ?></span>
                            <?= $fill($setting['text']) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        <?php if (!empty($help['recipes'])): ?>
            <div class="sig-pop-col" data-col="c">
                <h4><?= h(__('If you want…')) ?></h4>
                <ul class="sig-pop-recipes">
                    <?php foreach ($help['recipes'] as $recipe): ?>
                        <li>
                            <span class="want"><?= h($recipe['want']) ?></span>
                            <span class="do"><?= $fill($recipe['do'], true)
                                ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>
</div>
