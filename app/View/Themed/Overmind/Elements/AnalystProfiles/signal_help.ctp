<?php
/**
 * The body of a signal's "How it works" popover, cloned out of a
 * `<template>` by analyst-profile-help.js.
 *
 * @var string $signalId
 * @var array $help AnalystProfileFormTool::signalHelp()
 * @var bool $trustWeighted
 */
$values = $help['values'];

$token = function ($m) use ($values) {
    if (!isset($values[$m[1]])) {
        return $m[0];
    }
    $value = $values[$m[1]]['value'];
    if (is_bool($value)) {
        $value = $value ? 'true' : 'false';
    }
    return '<b class="sig-pop-v" data-ap-help-for="'
        . h($values[$m[1]]['input']) . '">'
        . h($value === null ? '?' : (string)$value) . '</b>';
};
$fill = function ($text) use ($token) {
    return preg_replace_callback('/\{([a-z0-9_]+)\}/', $token, h($text));
};

$keys = array_keys($values);
$code = function ($text) use ($keys) {
    $html = h($text);
    if (empty($keys)) {
        return $html;
    }
    $pattern = '/\b(' . implode('|', array_map(function ($key) {
        return preg_quote($key, '/');
    }, $keys)) . ')\b/';
    return preg_replace($pattern, '<code>$1</code>', $html);
};

$titleId = 'sig-pop-title-' . preg_replace('/[^a-z0-9_-]/i', '-', $signalId);
$readsValue = $help['axis'] === 'lean';
?>
<div class="sig-pop-body" aria-labelledby="<?= h($titleId) ?>">
    <div class="sig-pop-head">
        <div class="sig-pop-titles">
            <p class="sig-pop-title" id="<?= h($titleId) ?>"><?=
                h($help['name']) ?></p>
            <p class="sig-pop-id"><?= h($signalId) ?></p>
        </div>
        <button type="button" class="sig-pop-close" data-ap-help-close
                aria-label="<?= h(__('Close')) ?>">
            <i class="fa-solid fa-xmark" aria-hidden="true"></i>
        </button>
    </div>
    <div class="sig-pop-tags">
        <?php if ($readsValue): ?>
            <span class="pill t-missing"><?= h(__('reads the value')) ?></span>
        <?php else: ?>
            <span class="sig-tag"><b><?= h(__('signal strength')) ?></b></span>
        <?php endif; ?>
        <?php if ($trustWeighted): ?>
            <span class="sig-tag is-mult"><?= h(__('trust weighted')) ?></span>
        <?php endif; ?>
    </div>
    <div class="sig-pop-grid">
        <div class="sig-pop-col" data-col="a">
            <?php if (!empty($help['what'])): ?>
                <h4><?= h(__('What it looks at')) ?></h4>
                <p><?= h($help['what']) ?></p>
            <?php endif; ?>
            <?php if (!empty($help['how'])): ?>
                <h4><?= h(__('How it scores')) ?></h4>
                <p><?= $fill($help['how']) ?></p>
            <?php endif; ?>
            <p class="sig-pop-lands">
                <?= $readsValue
                    ? h(__('It argues whether the value is harmful or'
                        . ' harmless, so its points are weighed against'
                        . ' the reading and kept out of the signal'
                        . ' strength.'))
                    : h(__('Its points add up with the other signals\''
                        . ' into the signal strength: how well documented'
                        . ' the record is, whichever way it leans.')) ?>
                <?php if ($trustWeighted): ?>
                    <?= h(__('Each organisation\'s part is scaled by the'
                        . ' grade you gave it under Sources & reputation.')) ?>
                <?php endif; ?>
            </p>
            <?php if (!empty($help['note'])): ?>
                <p class="sig-pop-note">
                    <i class="fa-solid fa-circle-info" aria-hidden="true"></i>
                    <span><?= $fill($help['note']) ?></span>
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
                            <span class="do"><?= $code($recipe['do']) ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
    </div>
</div>
