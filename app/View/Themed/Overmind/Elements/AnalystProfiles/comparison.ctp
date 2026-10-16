<?php
/**
 * The values the analyst pinned, one row each, under both profiles.
 *
 * The point is the corpus rather than the value in front of you: a
 * change that quietly turned a known-benign value malicious is visible
 * without one page load per value. The arrows say which way the ledger
 * moved, not whether the move is right — that is the analyst's to
 * decide, and a design that coloured it otherwise would be making the
 * judgement the whole feature exists to hand over.
 *
 * An empty set is an instruction, not a blank table.
 *
 * @var array $comparison One headline per value
 * @var array $pinned The values in the set
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

$arrow = array('up' => '▲', 'down' => '▼', 'sideways' => '↔', 'none' => '—');
$tone = array('up' => 'd-up', 'down' => 'd-dn', 'sideways' => 'd-0',
    'none' => 'd-0');
?>
<?php
/*
 * The heading counts the rows, not the pinned set: a reader who
 * arrived from a value page has one row and nothing pinned, and a
 * heading reading *"your pinned values: 0"* above a row was the first
 * thing that read as a bug on the live page.
 */
?>
<div class="bench-sec" style="margin-top:1.1rem">
    <span><?= h(__('Values tested')) ?></span>
    <span class="num"><?= h(count($comparison)) ?></span>
</div>
<?php if (!empty($comparison)): ?>
    <p class="wb-sub mt-1 mb-1">
        <?= count($pinned) === 0
            ? h(__('None of them is pinned. A pinned value stays here on'
                . ' every profile you open.'))
            : h(sprintf(__n('%s of them is pinned.',
                '%s of them are pinned.', count($pinned)),
                count($pinned))) ?>
    </p>
<?php endif; ?>
<?php if (empty($comparison)): ?>
    <div class="wb-empty">
        <div class="fw-semibold"><?= h(__('Nothing pinned yet')) ?></div>
        <p class="mb-0 mt-1">
            <?= h(__('Pin a value to keep it here on every profile you'
                . ' open.')) ?>
        </p>
    </div>
<?php else: ?>
    <table class="wb-tbl">
        <thead>
            <tr>
                <th><?= h(__('Value')) ?></th>
                <th class="r"><?= h(__('Signal strength')) ?></th>
                <th class="wb-wide-only"><?= h(__('Band')) ?></th>
                <th class="r" style="width:2.5rem"></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($comparison as $row): ?>
                <?php
                $axes = $row['axes'];
                $lean = $axes['lean'];
                $band = $axes['band'];
                $note = null;
                if ($lean['after'] === 'none') {
                    $note = __('nothing to assess');
                } elseif (!empty($lean['changed'])) {
                    $note = sprintf(__('lean %1$s → %2$s'),
                        $lean['before'], $lean['after']);
                } elseif (!empty($band['changed'])) {
                    $note = __('band moved');
                }
                ?>
                <tr>
                    <td class="wb-id">
                        <?= h($row['value']) ?>
                        <?php if ($note !== null): ?>
                            <div class="wb-sub"><?= h($note) ?></div>
                        <?php endif; ?>
                    </td>
                    <td class="r num">
                        <?= h($axes['signal_strength']['before']) ?> &rarr;
                        <?= h($axes['signal_strength']['after']) ?>
                    </td>
                    <td class="wb-wide-only wb-sub">
                        <?php if (!empty($band['changed'])): ?>
                            <?= h($band['before']) ?> &rarr;
                            <b><?= h($band['after']) ?></b>
                        <?php else: ?>
                            <?= h($band['after']) ?>
                        <?php endif; ?>
                    </td>
                    <td class="r <?= h($tone[$row['direction']]) ?>">
                        <?= h($arrow[$row['direction']]) ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <p class="wb-sub mt-1 mb-0">
        <?= h(__('▲ and ▼ show which way the score moved, not whether the'
            . ' move is right.')) ?>
    </p>
<?php endif; ?>
