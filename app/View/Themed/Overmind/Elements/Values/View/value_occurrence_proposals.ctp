<?php
/**
 * What the pending proposals against one occurrence would change, as a
 * menu under its State badge. Accepting and discarding stay on the event,
 * which is where MISP checks who may do either.
 *
 * @var array $proposals From `ValueIntelligence::proposalChange()`, newest
 *     first
 */
$ops = array(
    'replace' => array(
        'label' => __('Changes the value'),
        'class' => 'text-warning-emphasis',
    ),
    'refile' => array(
        'label' => __('Keeps the value'),
        'class' => 'text-body-secondary',
    ),
    'delete' => array(
        'label' => __('Deletes it'),
        'class' => 'text-danger-emphasis',
    ),
    'none' => array(
        'label' => __('Changes nothing shown here'),
        'class' => 'text-body-secondary',
    ),
);
?>
<div class="dropdown-menu shadow-sm vp-occ-proposals">
    <?php foreach ($proposals as $index => $proposal): ?>
        <?php $op = $ops[$proposal['op']]; ?>
        <?php if ($index > 0): ?>
            <hr class="dropdown-divider">
        <?php endif; ?>
        <div class="vp-occ-proposal">
            <div class="vp-occ-proposal-head">
                <span class="fw-semibold"><?= h($proposal['org']) ?></span>
                <span class="text-muted">&middot;</span>
                <span class="text-muted"><?=
                    h(date('Y-m-d', $proposal['timestamp'])) ?></span>
                <span class="ms-auto small <?= h($op['class']) ?>"><?=
                    h($op['label']) ?></span>
            </div>
            <?php if ($proposal['op'] === 'delete'): ?>
                <div class="small text-muted">
                    <?= __('Proposes deleting this occurrence.') ?>
                </div>
            <?php elseif (!empty($proposal['change'])): ?>
                <?= $this->element('Values/View/value_change_table', array(
                    'changes' => $proposal['change'],
                )) ?>
            <?php endif; ?>
            <a class="small" href="<?= h($baseurl) ?>/events/view/<?=
                h($proposal['event_id']) ?>#tab-attributes"><?=
                __('Review on the event') ?></a>
        </div>
    <?php endforeach; ?>
</div>
