<?php
/**
 * What is in the wallet, and when it last moved.
 *
 * Balance and last movement, in that order, because a balance says
 * whether there is anything to trace and the movement says whether
 * tracing it is about now. A wallet holding funds that have not moved
 * in two years is a different case from one that moved this morning,
 * and the widget must not make them look alike.
 *
 * @var array $data
 */
$wallet = $data['wallet'];
?>
<div class="vp-rw-in vp-rw-crypto">
    <?php if ($wallet !== null && $wallet['balance'] !== null): ?>
        <div class="vp-rw-metric">
            <span class="vp-rw-metric-n"><?= h(rtrim(rtrim(
                number_format($wallet['balance'], 8), '0'), '.')) ?></span>
            <span class="vp-rw-metric-l"><?=
                h($wallet['symbol'] === null
                    ? __('held') : $wallet['symbol']) ?></span>
        </div>
    <?php elseif ($data['count'] > 0): ?>
        <div class="vp-rw-metric">
            <span class="vp-rw-metric-n"><?=
                h(number_format($data['count'])) ?></span>
            <span class="vp-rw-metric-l"><?= h(__n(
                'transaction', 'transactions', $data['count']
            )) ?></span>
        </div>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?= h(__('on chain')) ?></div>
    <?php endif; ?>

    <?php if ($data['last_movement'] !== null): ?>
        <div class="vp-rw-sub"><?= h(sprintf(
            __('last moved %s'),
            date('Y-m-d', $data['last_movement'])
        )) ?></div>
    <?php endif; ?>
    <?php if ($wallet !== null && $wallet['received'] !== null): ?>
        <div class="vp-rw-note"><?= h(sprintf(
            __('%s received'),
            rtrim(rtrim(number_format($wallet['received'], 8), '0'), '.')
        )) ?></div>
    <?php endif; ?>
</div>
