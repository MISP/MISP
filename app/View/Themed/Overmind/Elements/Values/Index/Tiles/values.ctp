<?php
/**
 * How many distinct values the instance stores.
 *
 * @var array|null $dictionary As ValueDictionaryStatsTool::summarise(), or
 *                             null while the first count is still running
 */
?>
<div class="vi-tile" data-vi-tile="values">
    <div class="vi-tile__label"><i class="fas fa-book vi-tile__icon" aria-hidden="true"></i><?= h(__('Distinct values')) ?></div>
<?php if ($dictionary === null): ?>
    <div class="vi-tile__value vi-tile__value--none"><?= h(__('Counting…')) ?></div>
    <div class="vi-tile__sub"><?= h(__(
        'the first count runs in the background and shows here once it is done.'
    )) ?></div>
<?php else: ?>
    <div class="vi-tile__value"><?= $dictionary['total_floor'] ? '≥&#8239;' : '' ?><?= h(number_format($dictionary['total'])) ?></div>
    <div class="vi-tile__sub"><?= h(__n(
        'value on this instance, stored once however many attributes carry it.',
        'values on this instance, each stored once however many attributes carry it.',
        $dictionary['total']
    )) ?></div>
<?php endif; ?>
</div>
