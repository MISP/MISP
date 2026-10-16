<?php
/**
 * The warninglists a value is checked against.
 *
 * Every profile draws a warninglist chip when a value is on a list,
 * and the chip is the one thing on the page that can stop a reader
 * taking a confident *Asserted threat* for a finished answer. What it
 * cannot say on its own is how much checking is behind it: a chip that
 * never appears means something different on an instance running eight
 * lists than on one running none.
 *
 * **Enabled, because that is the set that is actually consulted.**
 * `warninglists` holds every list MISP ships; only the enabled ones
 * are matched against a value, so a count of all 97 would describe a
 * capability rather than this instance's behaviour.
 *
 * **Instance policy, not anybody's activity**, which is what makes it
 * safe to show. It says how this instance is configured, and nothing
 * about what any organisation has looked at (D27).
 *
 * One statement over a 97-row table, measured at 1.3 ms.
 *
 * @var int $warninglists
 */
?>
<div class="vi-tile" data-vi-tile="warninglists">
    <div class="vi-tile__label"><i class="fas fa-shield-halved vi-tile__icon" aria-hidden="true"></i><?= h(__('Warninglists')) ?></div>
<?php if ($warninglists === 0): ?>
    <div class="vi-tile__value vi-tile__value--none">
        <?= h(__('None enabled')) ?>
    </div>
    <div class="vi-tile__sub"><?= h(__(
        'no value will be flagged as a known false positive.'
    )) ?></div>
<?php else: ?>
    <div class="vi-tile__value">
        <?= h(number_format($warninglists)) ?>
    </div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__('enabled %s, checked against every value.')),
        h(__n('warninglist', 'warninglists', $warninglists))
    ) ?></div>
<?php endif; ?>
</div>
