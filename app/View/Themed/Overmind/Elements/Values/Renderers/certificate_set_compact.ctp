<?php
/**
 * How many certificates, and whether the newest one is still good.
 *
 * The count is the headline and the newest validity window is the
 * qualifier, because a set of certificates is a history and its most
 * recent entry is what describes the host now.
 *
 * An expired certificate still being served is the one exception worth
 * a line of its own: it is a finding rather than a detail, and it is
 * the reason to open the full list.
 *
 * @var array $data
 */
$newest = $data['newest'];
?>
<div class="vp-rw-in vp-rw-cert">
    <div class="vp-rw-metric">
        <span class="vp-rw-metric-n"><?=
            h(number_format($data['count'])) ?></span>
        <span class="vp-rw-metric-l"><?= h(__n(
            'certificate', 'certificates', $data['count']
        )) ?></span>
    </div>
    <?php if ($newest !== null): ?>
        <?php if ($newest['subject'] !== null): ?>
            <div class="vp-rw-sub" title="<?=
                h($newest['subject']) ?>"><?= h($newest['subject']) ?></div>
        <?php endif; ?>
        <?php if ($newest['not_before'] !== null
            || $newest['not_after'] !== null): ?>
            <div class="vp-rw-note"><?= h(sprintf(
                '%s — %s',
                $newest['not_before'] === null
                    ? '?' : date('Y-m-d', $newest['not_before']),
                $newest['not_after'] === null
                    ? '?' : date('Y-m-d', $newest['not_after'])
            )) ?></div>
        <?php endif; ?>
    <?php endif; ?>
    <?php if ($data['expired'] > 0): ?>
        <div class="vp-rw-note vp-rw-split"><?= h(sprintf(
            __n('%s expired', '%s expired', $data['expired']),
            $data['expired']
        )) ?></div>
    <?php endif; ?>
</div>
