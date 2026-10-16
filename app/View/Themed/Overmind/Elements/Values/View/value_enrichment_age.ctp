<?php
/**
 * How long ago a module was asked, in the coarsest unit still true.
 *
 * The Enrichment tab gained a memory in phase 11 and this is the only
 * thing it says about where an answer came from: **when**, never who
 * (`13-auto-run.md` §8.2, D27). Naming the analyst who ran a module
 * would tell everyone in the organisation which colleague is looking
 * at which value — the same disclosure the page already refuses when
 * it declines to draw per-value ACL counts — and the store's `user_id`
 * exists for an audit rather than for a rail row.
 *
 * A plain partial, printing a phrase and nothing around it, so the
 * rail row and the cold pane cannot word the same fact differently.
 *
 * The phrase is relative because that is what a reader can act on, and
 * it freezes where it was rendered: the fragment is server-rendered
 * and a tab left open all afternoon still says two hours. That is the
 * same trade `value_read_age.ctp` makes, and for the same reason.
 *
 * @var int $askedAge Seconds since the run, 0 or more
 */
$askedAge = isset($askedAge) ? max(0, (int)$askedAge) : 0;

if ($askedAge < 60) {
    $when = __('just now');
} elseif ($askedAge < 3600) {
    $n = (int)round($askedAge / 60);
    $when = sprintf(__n('%d minute ago', '%d minutes ago', $n), $n);
} elseif ($askedAge < 172800) {
    $n = (int)round($askedAge / 3600);
    $when = sprintf(__n('%d hour ago', '%d hours ago', $n), $n);
} else {
    $n = (int)round($askedAge / 86400);
    $when = sprintf(__n('%d day ago', '%d days ago', $n), $n);
}
echo h($when);
