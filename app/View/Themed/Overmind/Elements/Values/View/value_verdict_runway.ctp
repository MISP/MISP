<?php
/**
 * The hero's shelf-life figure — relevance, read at a glance.
 *
 * The hero's third axis. Lean has the badge and signal strength the gauge;
 * relevance used to be the last clause of the sentence, which is where
 * a reader stops reading. Drawn the way the hover card draws its
 * runway: a label, the days as the figure, the state in small caps
 * under it and carried by ink weight rather than a hue, because the
 * lean owns the hue on this card.
 *
 * Nothing is drawn where there is no clock to run; the clock band
 * further down says why.
 *
 * @var array $relevance `$verdict['relevance']`
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$state = $relevance['state'] ?? null;
if ($state === null) {
    return;
}
$days = $relevance['runway_days'] ?? null;
$hint = ValueRelevanceTool::stateHint($state);
?>
<div class="vp-vc-runway vp-vc-runway-<?= h($state) ?>"<?= $hint === null
    ? ''
    : ' title="' . h($hint) . '"' ?>>
    <div class="vp-vc-runway-k"><?= h(__('Shelf life')) ?></div>
    <?php if ($days === null): ?>
        <div class="vp-vc-runway-n vp-vc-runway-absent">&mdash;</div>
    <?php elseif ($days === 0): ?>
        <div class="vp-vc-runway-n"
             title="<?= h(__('expires today')) ?>"><?= h(__('Today')) ?></div>
    <?php else: ?>
        <div class="vp-vc-runway-n"><?= h(abs($days)) ?><span
            class="vp-vc-runway-u"><?= h($days > 0
                ? __n('day left', 'days left', $days)
                : __n('day over', 'days over', -$days)) ?></span></div>
    <?php endif; ?>
    <div class="vp-vc-runway-s">
        <?= h(ValueRelevanceTool::stateLabel($state)) ?>
    </div>
    <?php if ($state !== 'uncertain' && !empty($relevance['uncertain'])): ?>
        <div class="vp-vc-runway-s vp-vc-runway-note"
             title="<?= h(ValueRelevanceTool::stateHint('uncertain')) ?>">
            <?= h(ValueRelevanceTool::stateLabel('uncertain')) ?>
        </div>
    <?php endif; ?>
</div>
