<?php
/**
 * How many platforms, and which — and what the identifier turned up in.
 *
 * The count leads and the platform names follow, which is the inverse
 * of most shapes here: the answer *is* the set, and no one platform in
 * it is more the answer than another.
 *
 * **Breaches are counted and never listed.** One address measured
 * against a live breach service came back with 214 of them, so a list
 * here is a scrollbar in a 190px box. The count, the year it reaches
 * back to, and whether passwords were among what was exposed are what
 * fit and what a reader acts on; the rest is the full rendering.
 *
 * **Whichever the value has leads**, because *0 accounts* is a poor
 * headline for an address that appears in two hundred breaches, and an
 * absent breach section is not a zero — nothing asked and nothing
 * found arrive here the same way, so neither is stated.
 *
 * @var array $data
 */
$platforms = $data['platforms'];
$accounts = $data['count'];
$breaches = $data['breach_count'];
$leads = $accounts > 0 || $breaches === 0;
$n = $leads ? $accounts : $breaches;
?>
<div class="vp-rw-in vp-rw-acct">
    <div class="vp-rw-metric">
        <span class="vp-rw-metric-n"><?= h(number_format($n)) ?></span>
        <span class="vp-rw-metric-l"><?= h($leads
            ? __n('account', 'accounts', $n)
            : __n('breach', 'breaches', $n)) ?></span>
    </div>
    <?php if (!empty($platforms)): ?>
        <ul class="vp-rw-set">
            <?php foreach (array_slice($platforms, 0, 4) as $one): ?>
                <li><?= h($one) ?></li>
            <?php endforeach; ?>
        </ul>
        <?php if (count($platforms) > 4): ?>
            <div class="vp-rw-note">+<?=
                h(count($platforms) - 4) ?></div>
        <?php endif; ?>
    <?php endif; ?>
    <?php
    /*
     * The second count, stated only where the first one was accounts.
     * Where breaches took the metric this would repeat it.
     */
    if ($breaches > 0):
        $since = $data['first_breach'] === null
            ? null : date('Y', $data['first_breach']);
        if ($leads) {
            $line = sprintf(
                __n('%s breach', '%s breaches', $breaches),
                number_format($breaches)
            );
            if ($since !== null) {
                $line = sprintf(__('%s since %s'), $line, $since);
            }
        } else {
            $line = $since === null
                ? null : sprintf(__('since %s'), $since);
        }
        if ($line !== null): ?>
            <div class="vp-rw-sub"><?= h($line) ?></div>
        <?php endif;
    endif; ?>
    <?php if ($data['passwords']): ?>
        <div class="vp-rw-note vp-rw-split"><?=
            h(__('passwords exposed')) ?></div>
    <?php endif; ?>
</div>
