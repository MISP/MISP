<?php
/**
 * The six facts an analyst reads before deciding whether to keep reading:
 * first seen, last seen, occurrences, events, organisations, sightings.
 *
 * Each cell jumps to the tab holding the rows behind the number, so no
 * figure on the strip is a dead end.
 *
 * @var array $facts
 */
?>
<div class="container-fluid">
    <div class="vp-fact-strip" data-tour="value-facts">
        <?php foreach ($facts as $fact): ?>
            <?php
            $tag = empty($fact['tab']) ? 'div' : 'a';
            $href = empty($fact['tab'])
                ? ''
                : ' href="#tab-' . h($fact['tab']) . '"';
            ?>
            <<?= $tag ?> class="vp-fact"<?= $href ?>>
                <span class="vp-fact-label"><?= h($fact['label']) ?></span>
                <span class="vp-fact-value"><?= h($fact['value']) ?></span>
                <?php if (!empty($fact['sub'])): ?>
                    <span class="vp-fact-sub"><?= h($fact['sub']) ?></span>
                <?php endif; ?>
            </<?= $tag ?>>
        <?php endforeach; ?>
    </div>
</div>
