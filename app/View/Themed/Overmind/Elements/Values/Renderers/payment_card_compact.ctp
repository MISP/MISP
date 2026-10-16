<?php
/**
 * Which scheme, and who issued it.
 *
 * @var array $data
 */
$card = $data['headline'];
?>
<div class="vp-rw-in vp-rw-card">
    <?php if ($card['scheme'] !== null): ?>
        <div class="vp-rw-head"><?= h($card['scheme']) ?></div>
    <?php elseif ($card['issuer'] !== null): ?>
        <div class="vp-rw-head" title="<?=
            h($card['issuer']) ?>"><?= h($card['issuer']) ?></div>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('card')) ?></div>
    <?php endif; ?>
    <?php if ($card['scheme'] !== null && $card['issuer'] !== null): ?>
        <div class="vp-rw-sub" title="<?=
            h($card['issuer']) ?>"><?= h($card['issuer']) ?></div>
    <?php endif; ?>
    <?php if ($card['iin'] !== null): ?>
        <div class="vp-rw-note font-monospace"><?=
            h($card['iin']) ?></div>
    <?php endif; ?>
    <?php if ($card['expires'] !== null): ?>
        <div class="vp-rw-note"><?= h(sprintf(
            __('expires %s'),
            $card['expires']
        )) ?></div>
    <?php endif; ?>
</div>
