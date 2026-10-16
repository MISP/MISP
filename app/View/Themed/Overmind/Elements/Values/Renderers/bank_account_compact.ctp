<?php
/**
 * Which institution, and where.
 *
 * @var array $data
 */
$account = $data['headline'];
?>
<div class="vp-rw-in vp-rw-bank">
    <?php if ($account['institution'] !== null): ?>
        <div class="vp-rw-head" title="<?=
            h($account['institution']) ?>"><?=
            h($account['institution']) ?></div>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('account')) ?></div>
    <?php endif; ?>
    <?php if ($account['country'] !== null): ?>
        <div class="vp-rw-sub"><?= h($account['country']) ?></div>
    <?php endif; ?>
    <?php if ($account['bic'] !== null): ?>
        <div class="vp-rw-note font-monospace"><?=
            h($account['bic']) ?></div>
    <?php endif; ?>
    <?php if ($account['holder'] !== null): ?>
        <div class="vp-rw-note" title="<?=
            h($account['holder']) ?>"><?= h($account['holder']) ?></div>
    <?php endif; ?>
</div>
