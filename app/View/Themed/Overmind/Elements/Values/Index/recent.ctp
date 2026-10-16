<?php
/**
 * Carried over — the values this reader last opened.
 *
 * The one block on this page whose rows are neither the reader's paste
 * nor an aggregate over `attributes`: it reads ten strings out of one
 * `user_settings` row that this reader put there by opening them
 * (`value-index.md` §7.4).
 *
 * **Yours alone, and it says so.** D27 refuses to name who ran an
 * enrichment because naming the runner tells the organisation which
 * colleague is looking at which value; a recently-viewed list anybody
 * else could read is that disclosure with a different label. The
 * sentence above the chips is not reassurance — it is the reason a
 * reader can use the block without thinking about who is watching.
 *
 * **No lean on the chip.** Ten assessments is ten engine runs spent
 * before the reader has pasted anything, on a block nobody has asked a
 * question of yet (`02a-contract.md` §12.7). The hover card answers
 * for the value under the cursor, at the moment there is one, and
 * costs nothing until then — so each chip is a hover trigger where the
 * instance has the card on, and a plain link where it does not.
 *
 * **A line, not a panel.** An empty one is a sentence in the future
 * tense rather than an empty box, because four empty boxes is what
 * makes a new install read as broken.
 *
 * @var array<array{value: string, at: int}> $recent Newest first
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
/*
 * `CakeTime` and not `$this->Time`. MISP replaces CakePHP's
 * `TimeHelper` wholesale with a two-method helper of its own — `time()`
 * and `date()` — so `$this->Time->timeAgoInWords()` reaches
 * `Helper::__call`, returns the empty string, and renders a chip with a
 * blank where the age goes. Nothing throws and the page looks finished.
 */
App::uses('CakeTime', 'Utility');

$hoverCard = (bool)Configure::read('MISP.value_hover_card');
?>
<div class="vi-recent">
<?php if (empty($recent)): ?>
    <p class="vi-recent__lead"><?= h(__(
        'Values you open will be listed here. Only you can see this'
        . ' list.'
    )) ?></p>
<?php else: ?>
    <p class="vi-recent__lead"><?= h(__(
        'Recently opened values. Only you can see this list.'
    )) ?></p>
    <div class="vi-recent__chips">
<?php   foreach ($recent as $entry): ?>
        <a class="vi-chip<?= $hoverCard ? ' vp-hc-trigger' : '' ?>"
           href="<?= h($this->Html->url(array(
               'controller' => 'values',
               'action' => 'view',
               ValueUrlTool::encode($entry['value']),
           ))) ?>"
<?php       if ($hoverCard): ?>
           data-vp-hc-value="<?= h(ValueUrlTool::encode($entry['value'])) ?>"
<?php       endif; ?>
           ><span class="vi-chip__value"><?= h($entry['value']) ?></span>
            <span class="vi-chip__at"><?= h(
                CakeTime::timeAgoInWords($entry['at'], array(
                    /*
                     * One unit rather than two past a day: a line of
                     * chips has room for *1 day ago* and not for *1
                     * day, 6 hours ago*, and the hour is not what a
                     * reader scanning this line is asking about.
                     * Below a day the default is already one unit.
                     */
                    'accuracy' => array('day' => 'day'),
                ))
            ) ?></span></a>
<?php   endforeach; ?>
    </div>
<?php endif; ?>
</div>
