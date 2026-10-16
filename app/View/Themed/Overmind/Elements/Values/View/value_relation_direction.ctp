<?php
/**
 * The one direction chip the two hand-written sections wear.
 *
 * Both of them relate this value to something at the other end of an
 * arrow somebody drew, and both used to say so in their own words: the
 * references table printed *points at it* / *points away from it* as
 * plain grey text, and the asserted claims printed `INBOUND` /
 * `OUTBOUND` in a bordered pill. One convention underneath, two
 * vocabularies and two shapes on one tab.
 *
 * The pill won, and the two words with it. The prose form is nine
 * words to say what the arrow already shows, it wraps in a table cell
 * narrow enough to hold a relationship name, and `inbound` is the word
 * the section's own text, the model and `ObjectReference` already use.
 * The sentence it replaced is not lost — it is the chip's tooltip, and
 * it says what the direction means *in that section's terms*, which is
 * the one thing the two sections genuinely do not share: a reference
 * relates two objects, a claim relates an analyst's statement to a
 * value.
 *
 * The arrow takes the panel's colour, so the chip reads as part of the
 * section it sits in without either section having to restyle it.
 *
 * @var string $direction      `inbound` or `outbound`
 * @var string $directionTitle What the direction means here
 */
$directionTitle = $directionTitle ?? '';
$inbound = $direction === 'inbound';
?>
<span class="vp-rel-dir <?= $inbound
        ? 'vp-rel-dir-in'
        : 'vp-rel-dir-out' ?>"<?php
    if ($directionTitle !== ''): ?> title="<?= h($directionTitle) ?>"<?php
    endif; ?>>
    <i class="fas <?= $inbound
        ? 'fa-arrow-left-long'
        : 'fa-arrow-right-long' ?>"></i>
    <?= h($inbound ? __('inbound') : __('outbound')) ?>
</span>
