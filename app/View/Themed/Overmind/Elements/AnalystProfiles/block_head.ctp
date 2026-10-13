<?php
/**
 * A block's title, axis tag and blurb, the same for every block kind.
 *
 * The blurb's first sentence stays on screen and the rest goes behind
 * an `i`.
 *
 * @var array $block
 */
$blurb = isset($block['blurb']) ? trim($block['blurb']) : '';
$rest = '';
if ($blurb !== '' && preg_match('/^(.+?[.!?])\s+(.*)$/s', $blurb, $m)) {
    $blurb = $m[1];
    $rest = $m[2];
}
?>
<?php if (!empty($block['title'])): ?>
    <p class="wb-h wb-bh">
        <?= h($block['title']) ?>
        <?php if (!empty($block['axis'])): ?>
            <span class="wb-ax"><?= h($block['axis']) ?></span>
        <?php endif; ?>
    </p>
<?php endif; ?>
<?php if ($blurb !== ''): ?>
    <p class="wb-blurb">
        <?= h($blurb) ?>
        <?php if ($rest !== ''): ?>
            <a href="#" class="wb-i" onclick="return false;"
               title="<?= h($rest) ?>">i</a>
        <?php endif; ?>
    </p>
<?php endif; ?>
