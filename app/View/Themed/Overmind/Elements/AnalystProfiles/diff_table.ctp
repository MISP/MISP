<?php
/**
 * One row per ledger row, both contributions and the delta.
 *
 * **The delta column is the one place a red/green pair does real
 * work**, so it uses `--vp-dir-with` and `--vp-dir-against` — the
 * lean's own pair — rather than a Bootstrap state that means
 * something else. It is no longer the pair the value page's *ledger*
 * uses: since `review-2026-09-13.md` §D1 those rows resolve to
 * `--vp-weighs-carries` / `--vp-weighs-lacks`, because a record
 * weighs the same under either reading. What the two surfaces still
 * share is the lean's pair, on the surfaces whose subject is the
 * lean (`ValueLean::directionStyle()`). Here the subject is *did
 * this edit move the number*, which is a direction of its own.
 *
 * The rows span both axes (`ValueVerdictDiffTool::diff()`), so the
 * signal-strength-axis subset sums to the signal strength exactly and the lean
 * rows to `lean_weight` — that exactness is the whole reason this diff is
 * arithmetic rather than impressionistic. The footer checks `sums`,
 * which the tool narrows to the signal-strength axis, and says so per column
 * rather than asserting it.
 *
 * @var array $detail The diff
 * @var bool $full Every row, or only the ones that moved
 */
$rows = $detail['rows'];
if (!$full) {
    $rows = array();
    foreach ($detail['rows'] as $row) {
        if ($row['state'] !== 'same') {
            $rows[] = $row;
        }
    }
}
$stateLabel = array(
    'changed' => __('changed'),
    'appeared' => __('appeared'),
    'vanished' => __('vanished'),
    'same' => __('unchanged'),
);
$direction = function ($delta) {
    if ($delta > 0) {
        return 'd-up';
    }
    return $delta < 0 ? 'd-dn' : 'd-0';
};
$number = function ($value) {
    return $value === null ? '—' : (string)$value;
};
?>
<?php if (empty($detail['rows'])): ?>
    <div class="wb-empty">
        <div class="fw-semibold"><?= h(__('No ledger')) ?></div>
        <p class="mb-0 mt-1"><?= h(__('Neither profile finds anything to'
            . ' weigh on this value, so there is nothing to compare.')) ?></p>
    </div>
<?php else: ?>
    <?php if (empty($detail['moved'])): ?>
        <div class="wb-note mb-2">
            <b><?= h(__('No change.')) ?></b>
            <?= h(sprintf(__n(
                'The candidate scores this value exactly as the profile'
                    . ' in force does: %s row, same contribution.',
                'The candidate scores this value exactly as the profile'
                    . ' in force does: %s rows, same contributions.',
                count($detail['rows'])
            ), count($detail['rows']))) ?>
        </div>
    <?php endif; ?>
<?php endif; ?>
<?php if (!empty($rows)): ?>
    <table class="wb-tbl">
        <thead>
            <tr>
                <th style="width:26%"><?= h(__('Signal')) ?></th>
                <?php if ($full): ?>
                    <th class="wb-wide-only" style="width:26%">
                        <?= h(__('What it read on this value')) ?>
                    </th>
                <?php endif; ?>
                <th class="r" style="width:9%"><?= h(__('In force')) ?></th>
                <th class="r" style="width:9%"><?= h(__('Candidate')) ?></th>
                <th class="r" style="width:8%">&Delta;</th>
                <th style="width:9%"></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($rows as $row): ?>
                <tr class="<?= $row['state'] === 'same' ? '' : 'is-hot' ?>">
                    <td>
                        <div class="wb-id fw-semibold"><?= h($row['id']) ?></div>
                        <?php if (!empty($row['signal'])): ?>
                            <div class="wb-sub"><?= h($row['signal']) ?></div>
                        <?php endif; ?>
                        <?php if (!empty($row['group'])): ?>
                            <div class="mt-1">
                                <span class="pill t-plain"><?= h($row['group']) ?></span>
                            </div>
                        <?php endif; ?>
                    </td>
                    <?php if ($full): ?>
                        <td class="wb-wide-only wb-sub">
                            <?= h((string)$row['evidence']) ?>
                        </td>
                    <?php endif; ?>
                    <td class="r num"><?= h($number($row['before'])) ?></td>
                    <td class="r num fw-bold"><?= h($number($row['after'])) ?></td>
                    <td class="r num <?= h($direction($row['delta'])) ?>">
                        <?= h($row['delta'] > 0 ? '+' . $row['delta'] : $row['delta']) ?>
                    </td>
                    <td>
                        <?php if ($row['state'] === 'same'): ?>
                            <span class="wb-sub"><?= h($stateLabel['same']) ?></span>
                        <?php else: ?>
                            <span class="pill t-force">
                                <?= h($stateLabel[$row['state']]) ?>
                            </span>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
        <tfoot>
            <tr>
                <td<?= $full ? ' colspan="2"' : '' ?> class="wb-sub">
                    <?= h(sprintf(__n(
                        '%s row did not move',
                        '%s rows did not move',
                        count($detail['rows']) - count($detail['moved'])
                    ), count($detail['rows']) - count($detail['moved']))) ?>
                </td>
                <td class="r num"><?= h($detail['totals']['before']) ?></td>
                <td class="r num"><?= h($detail['totals']['after']) ?></td>
                <td class="r num <?= h($direction($detail['totals']['delta'])) ?>">
                    <?= h($detail['totals']['delta'] > 0
                        ? '+' . $detail['totals']['delta']
                        : $detail['totals']['delta']) ?>
                </td>
                <td></td>
            </tr>
        </tfoot>
    </table>
    <?php if (empty($detail['sums']['ok'])): ?>
        <div class="wb-note bad mt-2">
            <b><?= h(__('A column does not add up.')) ?></b>
            <?= h(sprintf(
                __('The rows in force sum to %1$s against a signal'
                    . ' strength of %2$s, and the candidate\'s to %3$s against'
                    . ' %4$s. These should match — the comparison above'
                    . ' is unreliable until they do.'),
                $detail['sums']['before']['ledger'],
                $detail['sums']['before']['signal_strength'],
                $detail['sums']['after']['ledger'],
                $detail['sums']['after']['signal_strength']
            )) ?>
        </div>
    <?php endif; ?>
<?php endif; ?>

<?php if (!empty($detail['not_counted'])): ?>
    <div class="bench-sec" style="margin-top:1.1rem">
        <span><?= h(__('Not counted')) ?></span>
        <span class="num"><?= h(count($detail['not_counted'])) ?></span>
    </div>
    <table class="wb-tbl">
        <tbody>
            <?php foreach ($detail['not_counted'] as $entry): ?>
                <tr>
                    <td>
                        <div class="wb-id"><?= h($entry['id']) ?></div>
                        <?php if (!empty($entry['note'])): ?>
                            <div class="wb-sub"><?= h($entry['note']) ?></div>
                        <?php endif; ?>
                    </td>
                    <td class="r wb-sub"><?= h(isset($entry['state'])
                        ? $entry['state'] : '') ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>
