<?php
/**
 * The verdict on one value under both profiles, as one card: the line
 * that says whether it changes, the three readings side by side — what
 * the record asserts (lean), how well that is evidenced (signal strength
 * and its band), whether it still holds (relevance) — and the dates the
 * relevance clock read.
 *
 * @var array $detail The diff, ValueVerdictDiffTool
 * @var array|null $dates The value's dates, for the relevance clock
 * @var int|null $lastSighting
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$axes = $detail['axes'];
$runway = $axes['relevance']['runway'] ?? null;
$or = function ($value, $fallback) {
    return $value === null ? $fallback : $value;
};
$tiles = array(
    'lean' => array(
        'label' => __('Lean'),
        'hint' => __('what the record asserts'),
        'was' => $or($axes['lean']['before'], __('none')),
        'now' => $or($axes['lean']['after'], __('none')),
        'changed' => !empty($axes['lean']['changed']),
    ),
    'strength' => array(
        'label' => __('Signal strength'),
        'hint' => __('how well it is evidenced'),
        'was' => $axes['signal_strength']['before'],
        'now' => $axes['signal_strength']['after'],
        'bands' => array($axes['band']['before'], $axes['band']['after']),
        'delta' => $detail['totals']['delta'],
        'changed' => !empty($axes['signal_strength']['changed'])
            || !empty($axes['band']['changed']),
    ),
    'relevance' => array(
        'label' => __('Relevance'),
        'hint' => __('whether it still holds'),
        'was' => $or($axes['relevance']['before'], __('no clock')),
        'now' => $or($axes['relevance']['after'], __('no clock')),
        'changed' => !empty($axes['relevance']['changed']),
    ),
);
$changes = count(array_filter($tiles, function ($tile) {
    return $tile['changed'];
}));
$rule = $axes['rule']['after'];
?>
<section class="ap-cmp-card ap-cmp-verdict<?= $changes === 0 ? '' : ' is-changed' ?>">
    <header class="ap-cmp-card-h">
        <i class="fas fa-<?= $changes === 0 ? 'equals' : 'arrow-right-arrow-left' ?>" aria-hidden="true"></i>
        <span class="ap-cmp-card-t">
            <?php if ($changes === 0): ?>
                <b><?= h(__('Same verdict.')) ?></b> <?= h(__('The candidate reads this'
                    . ' value the way the profile in force does.')) ?>
            <?php else: ?>
                <b><?= h(sprintf(__n('%s reading of 3 changes.',
                    '%s readings of 3 change.', $changes), $changes)) ?></b>
                <?= h(__('The changed ones are highlighted.')) ?>
            <?php endif; ?>
        </span>
    </header>
    <div class="ap-cmp-card-b">
        <div class="ap-cmp-tiles">
            <?php foreach ($tiles as $id => $tile): ?>
                <div class="ap-cmp-tile<?= $tile['changed'] ? ' is-changed' : '' ?>">
                    <div class="ap-cmp-tile-h">
                        <span class="k"><?= h($tile['label']) ?></span>
                        <span class="ap-cmp-flag"><?= h($tile['changed']
                            ? __('changes') : __('same')) ?></span>
                    </div>
                    <?php foreach (array('was' => __('in force'), 'now' => __('candidate')) as $side => $who): ?>
                        <div class="ap-cmp-line is-<?= $side ?>">
                            <span class="ap-key-dot" aria-hidden="true"></span>
                            <span class="who"><?= h($who) ?></span>
                            <b class="<?= $id === 'strength' ? 'num' : '' ?>"><?= h($tile[$side]) ?></b>
                            <?php if (isset($tile['bands'])): ?>
                                <span class="pill t-plain"><?= h($tile['bands'][$side === 'was' ? 0 : 1]) ?></span>
                            <?php endif; ?>
                            <?php if ($side === 'now' && !empty($tile['delta'])): ?>
                                <span class="ap-delta num <?= $tile['delta'] > 0 ? 'd-up' : 'd-dn' ?>"><?=
                                    h($tile['delta'] > 0 ? '+' . $tile['delta'] : $tile['delta']) ?></span>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                    <div class="ap-cmp-hint"><?= h($tile['hint']) ?></div>
                    <?php if ($id === 'relevance'): ?>
                        <?= $this->element('AnalystProfiles/runway', array('runway' => $runway)) ?>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
        <?php if (!empty($rule)): ?>
            <div class="wb-note warn mt-3 mb-0">
                <b><?= h($axes['lean']['after']) ?></b>
                &mdash; <?= h($rule['prose']) ?>
                <?php if (!empty($rule['evidence'])): ?>
                    <div class="wb-sub mt-1"><?= h($rule['evidence']) ?></div>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
    <?php if (!empty($dates) && !empty($runway['clock'])): ?>
        <div class="ap-cmp-card-f">
            <?= $this->element('Values/View/value_date_sources', array(
                'facts' => $dates,
                'clockKind' => $runway['clock']['kind'] ?? null,
                'clockLabel' => ValueRelevanceTool::clockLabel(
                    $runway['clock']['setting'] ?? null
                ),
                'lastSighting' => $lastSighting ?? null,
                'sightingTotal' => 0,
                'roomy' => true,
            )) ?>
        </div>
    <?php endif; ?>
</section>
