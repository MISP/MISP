<?php
/**
 * What has reset this clock — the relevance axis's evidence rows.
 *
 * The corroboration timeline, newest first and capped: a value
 * corroborated forty times does not need forty rows to make the point,
 * and the newest one is the clock. The cap is a cap and not a
 * permission, so it says how many it left out
 * (`value-intelligence-live/00-contract.md` §14.6).
 *
 * Shared with the Assessment tab's clock band, where it is the nearest
 * thing the relevance axis has to the signal-strength ledger: the dates that
 * produced the number, each attributed, with the one currently holding
 * it marked. Signal strength shows every signal that moved it; this shows every
 * observation that moved the clock. Extracted rather than rewritten for
 * the reason `value_relevance_facts.ctp` gives at length.
 *
 * @var array $clock The `relevance.clock` block — `events` and the
 *                   stamp currently in force
 * @var int $cap     How many rows to draw before counting the rest
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$events = array_reverse($clock['events']);
$cap = isset($cap) ? (int)$cap : 6;
$shown = array_slice($events, 0, $cap);
?>
<div>
    <div class="vp-shelf-prov">
        <?= h(__('What has reset this clock')) ?>
    </div>
    <ul class="vp-shelf-events">
        <?php foreach ($shown as $i => $event): ?>
            <?php $hint = ValueRelevanceTool::kindHint($event['kind']); ?>
            <li class="vp-shelf-event<?= $i === 0
                ? ' vp-shelf-event-held'
                : '' ?>">
                <span class="vp-shelf-event-date">
                    <?= h(date('Y-m-d', $event['at'])) ?>
                </span>
                <span class="vp-shelf-event-who">
                    <?= h(empty($event['by'])
                        ? __('unnamed')
                        : $event['by']) ?>
                </span>
                <span class="vp-shelf-event-kind"<?= $hint === null
                    ? ''
                    : ' title="' . h($hint) . '"' ?>>
                    <?= h(ValueRelevanceTool::kindLabel($event['kind'])) ?>
                </span>
            </li>
        <?php endforeach; ?>
    </ul>
    <?php if (count($events) > count($shown)): ?>
        <div class="vp-shelf-prov">
            <?= h(sprintf(
                __n(
                    '%s earlier confirmation is not listed.',
                    '%s earlier confirmations are not listed.',
                    count($events) - count($shown)
                ),
                count($events) - count($shown)
            )) ?>
        </div>
    <?php endif; ?>
</div>
