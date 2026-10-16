<?php
/**
 * How old a held read is, in words a reader can act on.
 *
 * Three panels on the Relationships tab now print this — the
 * co-occurrence section, whose scan is held for five minutes, and the
 * two rail cards, whose numbers come from the digest built off that same
 * scan. The rule it exists to serve is §16.7's: a cached read that does
 * not say how old it is is the reason a window this long would otherwise
 * be a trap.
 *
 * The phrase is relative because that is what a reader can use; the
 * exact stamp goes in the `title`, and it is the half that stays true if
 * the tab is left open, because the fragment is server-rendered and the
 * words freeze where they were.
 *
 * @var int $readAt Unix stamp of the read, 0 if unknown
 * @var string|null $prefix Sentence to wrap the phrase, with one %s
 */
$readAt = isset($readAt) ? (int)$readAt : 0;
$prefix = isset($prefix) && $prefix !== null ? $prefix : __('Scanned %s.');

$age = $readAt > 0 ? max(0, time() - $readAt) : null;
if ($age === null || $age < 5) {
    $when = __('just now');
} elseif ($age < 60) {
    $when = sprintf(__n('%d second ago', '%d seconds ago', $age, $age));
} else {
    $minutes = (int)round($age / 60);
    $when = sprintf(
        __n('%d minute ago', '%d minutes ago', $minutes, $minutes)
    );
}
?>
<span<?= $readAt > 0
    ? ' title="' . h(sprintf(
        __('Scanned at %s'),
        date('Y-m-d H:i:s', $readAt)
    )) . '"'
    : '' ?>><?= h(sprintf($prefix, $when)) ?></span>
