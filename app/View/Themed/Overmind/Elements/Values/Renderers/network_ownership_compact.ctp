<?php
/**
 * Whose address this is, in one line and a number.
 *
 * The AS number is the identifier and the holder is what a person
 * reads, so the holder is the headline and the number sits under it —
 * the reverse of how the template orders them.
 *
 * @var array $data
 */
$as = $data['headline'];
?>
<div class="vp-rw-in vp-rw-asn">
    <?php if ($as === null): ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('announced')) ?></div>
    <?php else: ?>
        <div class="vp-rw-head" title="<?= h((string)$as['holder']) ?>"><?=
            h($as['holder'] === null ? $as['asn'] : $as['holder']) ?></div>
        <div class="vp-rw-sub font-monospace"><?= h($as['asn']) ?><?php
            if ($as['country'] !== null): ?>
            <span class="vp-rw-code"><?= h($as['country']) ?></span>
        <?php endif; ?></div>
        <?php if (!empty($as['prefixes'])): ?>
            <div class="vp-rw-metric">
                <span class="vp-rw-metric-n"><?=
                    h(number_format(count($as['prefixes']))) ?></span>
                <span class="vp-rw-metric-l"><?= h(__n(
                    'prefix', 'prefixes', count($as['prefixes'])
                )) ?></span>
            </div>
            <?php
            /*
             * The first prefix, monospaced, because it is the one fact
             * here a reader may want to copy — and one is what the
             * height allows once the count is drawn.
             */
            ?>
            <div class="vp-rw-note font-monospace"><?=
                h($as['prefixes'][0]) ?></div>
        <?php endif; ?>
    <?php endif; ?>
    <?php if (count($data['systems']) > 1): ?>
        <div class="vp-rw-note"><?= h(sprintf(
            __('%s systems'),
            count($data['systems'])
        )) ?></div>
    <?php endif; ?>
</div>
