<?php
/**
 * The falsification lines, without the card around them.
 *
 * Extracted so the Assessment tab's aside and the Overview's assessment
 * card draw one set of rows rather than two renderings of one array.
 *
 * The wrapper is the caller's: the aside puts the actions in the same
 * flex column and the card does not.
 *
 * @var array $changers From `verdict['changers']`
 */
?>
<?php foreach ($changers as $changer): ?>
    <?php
    // The condition in bold, then what it would do.
    $text = (string)$changer['text'];
    $lead = null;
    foreach (array(' — ', ': ') as $cut) {
        $at = mb_strpos($text, $cut);
        if ($at !== false && $at > 0) {
            $lead = array(mb_substr($text, 0, $at), mb_substr($text, $at));
            break;
        }
    }
    ?>
    <div class="vp-changer">
        <span class="vp-changer-arrow vp-changer-arrow-<?=
            h($changer['direction']) ?>" aria-hidden="true">
            <?= $changer['direction'] === 'up'
                ? '&#9650;'
                : '&#9660;' ?>
        </span>
        <span><?php if ($lead === null): ?><?= h($text) ?><?php else: ?><strong><?= h($lead[0]) ?></strong><?= h($lead[1]) ?><?php endif; ?></span>
    </div>
<?php endforeach; ?>
