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
<section class="ap-cmp-card">
<header class="ap-cmp-card-h">
    <span class="ap-cmp-card-t"><?= h(__('Values tested')) ?></span>
    <span class="ap-cmp-card-aside">
        <?php if (empty($comparison)): ?>
            <?= h(__('none')) ?>
        <?php elseif (count($pinned) === 0): ?>
            <?= h(sprintf(__n('%s value, none pinned', '%s values, none pinned',
                count($comparison)), count($comparison))) ?>
        <?php else: ?>
            <?= h(sprintf(__('%1$s values, %2$s pinned'), count($comparison), count($pinned))) ?>
        <?php endif; ?>
    </span>
</header>
<div class="ap-cmp-card-b">
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
                <th class="r ap-was"><?= h(__('In force')) ?></th>
                <th class="r ap-now"><?= h(__('Candidate')) ?></th>
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
                <tr class="<?= $row['direction'] === 'none' ? '' : 'is-hot' ?>">
                    <td class="wb-id">
                        <?= h($row['value']) ?>
                        <?php if ($note !== null): ?>
                            <div class="wb-sub"><?= h($note) ?></div>
                        <?php endif; ?>
                    </td>
                    <td class="r num ap-was"><?= h($axes['signal_strength']['before']) ?></td>
                    <td class="r num ap-now"><?= h($axes['signal_strength']['after']) ?></td>
                    <td class="wb-wide-only">
                        <?php if (!empty($band['changed'])): ?>
                            <span class="ap-was"><?= h($band['before']) ?></span> &rarr;
                            <span class="ap-cmp-flag"><?= h($band['after']) ?></span>
                        <?php else: ?>
                            <span class="wb-sub"><?= h($band['after']) ?></span>
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
</div>
</section>
