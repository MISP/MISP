<?php
/**
 * The enrichment store, as a tile.
 *
 * It answers the question the run store generates and nothing else on
 * any page answers (`value-index.md` §7.7, D25): why a value's
 * Enrichment tab replied instantly, and why pressing *run* on a fresh
 * answer changes nothing. Both have one cause — this organisation
 * already holds an answer and it is younger than the reuse window.
 *
 * **A tile rather than a line in the conditions strip.** The strip
 * says under what *rules* the session is worked — whose thresholds
 * decide an assessment — and every sentence in it is a condition the
 * reader cannot change by working. A count is not that: it is a
 * measurement, it moves as the organisation enriches, and a number
 * that moves set as running prose is a number nobody reads twice.
 *
 * **The count is the value and the window is the caption**, which is
 * the one non-obvious thing here. A stat tile's value slot is for the
 * figure that moves; `max_age_hours` is a setting somebody chose, and
 * giving it a tile of its own beside the count would claim the two are
 * the same kind of fact. It qualifies the count instead.
 *
 * **Proportional figures, not tabular.** `tabular-nums` gives every
 * digit the width of a `0`, which aligns columns and makes a large
 * standalone number look gappy. This page's tabular figures are in the
 * worklist's columns, where they belong.
 *
 * **A count and a window, and nothing else.** The survey asked for
 * *recently enriched values*; that is withdrawn, because a list of
 * what an organisation recently enriched is a list of what it is
 * currently investigating. No value, no module name and no timestamp
 * reaches this tile by construction rather than by filtering — the
 * model hands over two integers.
 *
 * **Your organisation's, said in those words.** The store is
 * org-scoped, so a reader comparing this figure with a colleague's
 * finds the same one and a reader in another organisation a different
 * one. A tile saying *this instance* would be both wrong and a hint
 * about somebody else's activity.
 *
 * **An empty store is words, not a zero.** A `0` in the value slot
 * reads as a fault on a page whose whole business is telling an honest
 * absence from a broken one. The window is still said, because it is
 * what will happen to the first answer.
 *
 * @var array{count: int, max_age_hours: int} $store
 */
$hours = (int)$store['max_age_hours'];
/*
 * One clause, shared by both states: what the window says is true of
 * an answer that exists and of one that does not exist yet.
 */
$window = sprintf(
    h(__n(
        'Each result is kept %s hour before a module is queried again',
        'Each result is kept %s hours before a module is queried again',
        $hours
    )),
    '<b>' . h(number_format($hours)) . '</b>'
);
?>
<div class="vi-tile" data-vi-tile="store">
    <div class="vi-tile__label"><i class="fas fa-database vi-tile__icon" aria-hidden="true"></i><?= h(__('Enrichment cache')) ?></div>
<?php if ($store['count'] === 0): ?>
    <div class="vi-tile__value vi-tile__value--none">
        <?= h(__('None yet')) ?>
    </div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__(
            'no enrichment results cached for your organisation. %s.'
        )),
        $window
    ) ?></div>
<?php else: ?>
    <div class="vi-tile__value"><?= h(number_format($store['count'])) ?></div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__('%s cached for your organisation. %s.')),
        h(__n(
            'enrichment result',
            'enrichment results',
            $store['count']
        )),
        $window
    ) ?></div>
<?php endif; ?>
</div>
