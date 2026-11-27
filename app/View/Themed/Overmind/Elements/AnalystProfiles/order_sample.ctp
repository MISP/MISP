<?php
/**
 * One shape's sample, drawn by its own compact template in a frame that
 * copies an Overview strip cell. Decoration only: the tile is the control.
 *
 * @var string $key Shape id
 * @var array $samples The block's `samples`
 */
$drawing = $samples['drawings'][$key] ?? null;
?>
<div class="ap-order-sample<?= $drawing === null ? ' is-none' : '' ?>"
     data-ap-sample-for="<?= h($key) ?>" aria-hidden="true" inert>
    <?php if ($drawing === null): ?>
        <span class="ap-order-sample-none"><?= h($samples['none']) ?></span>
    <?php else: ?>
        <div class="ap-order-sample-head">
            <span class="ap-order-sample-name"><?=
                h($samples['label']) ?></span>
            <?php if (!empty($drawing['modules'])): ?>
                <span class="ap-order-sample-src font-monospace"><?=
                    h(implode(', ', $drawing['modules'])) ?></span>
            <?php endif; ?>
        </div>
        <?= $this->element($drawing['compact'], array(
            'data' => $drawing['data'],
        )) ?>
    <?php endif; ?>
</div>
