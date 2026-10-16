<?php
/**
 * Values MISP has stopped correlating because they match more attributes
 * than the correlation limit allows.
 *
 * @var array{count: int, limit: int, review: bool} $overCorrelating
 */
$limit = '<b>' . h(number_format($overCorrelating['limit'])) . '</b>';
$review = $overCorrelating['review'] && $overCorrelating['count'] > 0
    ? ' <a class="vi-tile__link" href="' . h($this->Html->url(array(
        'controller' => 'correlations',
        'action' => 'overCorrelations',
    ))) . '">' . h(__('Review')) . '</a>'
    : '';
?>
<div class="vi-tile" data-vi-tile="over-correlating">
    <div class="vi-tile__label"><i class="fas fa-link-slash vi-tile__icon" aria-hidden="true"></i><?= h(__('Too common to correlate')) ?></div>
<?php if ($overCorrelating['count'] === 0): ?>
    <div class="vi-tile__value vi-tile__value--none"><?= h(__('None')) ?></div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__('no value matches more than %s attributes, so every value still correlates.')),
        $limit
    ) ?></div>
<?php else: ?>
    <div class="vi-tile__value"><?= h(number_format($overCorrelating['count'])) ?></div>
    <div class="vi-tile__sub"><?= sprintf(
        h(__n(
            'value matches more than %s attributes, so MISP no longer correlates it.',
            'values match more than %s attributes, so MISP no longer correlates them.',
            $overCorrelating['count']
        )),
        $limit
    ) ?><?= $review ?></div>
<?php endif; ?>
</div>
