<?php
/**
 * The falsification lines, without the card around them.
 *
 * Extracted so the Assessment tab's aside and the Overview's assessment
 * card draw one set of rows rather than two renderings of one array —
 * the rule `value_analyst_tug.ctp` was extracted under, and the reason
 * the Lifetime card and the clock band cannot disagree.
 *
 * The wrapper is the caller's: the aside puts the actions in the same
 * flex column and the card does not.
 *
 * @var array $changers From `verdict['changers']`
 */
?>
<?php foreach ($changers as $changer): ?>
    <div class="vp-changer">
        <span class="vp-changer-arrow vp-changer-arrow-<?=
            h($changer['direction']) ?>">
            <?= $changer['direction'] === 'up'
                ? '&#9650;'
                : '&#9660;' ?>
        </span>
        <span><?= h($changer['text']) ?></span>
    </div>
<?php endforeach; ?>
