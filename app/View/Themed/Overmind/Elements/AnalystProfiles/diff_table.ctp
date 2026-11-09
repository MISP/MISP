<?php
/**
 * The ledger under both profiles: first the rows the candidate moves,
 * each as the in-force number beside the candidate's with a bar for
 * each, then the rows it leaves alone, folded behind a click.
 *
 * In force is grey and the candidate the primary colour, as everywhere
 * in the comparison. The delta keeps `--vp-dir-with` and
 * `--vp-dir-against` (`d-up`/`d-dn`): its subject is which way this
 * candidate moved the number, a direction of its own.
 *
 * The rows span both axes (`ValueVerdictDiffTool::diff()`), so the
 * signal-strength subset sums to the signal strength exactly and the
 * lean rows to `lean_weight`. The footer checks `sums`, which the tool
 * narrows to the signal-strength axis, and says so per column rather
 * than asserting it.
 *
 * @var array $detail The diff
 */
$moved = array();
$still = array();
$scale = 1;
foreach ($detail['rows'] as $row) {
    if ($row['state'] === 'same') {
        $still[] = $row;
    } else {
        $moved[] = $row;
    }
    $scale = max($scale, abs((int)$row['before']), abs((int)$row['after']));
}
$stateLabel = array(
    'appeared' => __('appeared'),
    'vanished' => __('vanished'),
);
$signed = function ($value) {
    if ($value === null) {
        return '—';
    }
    return $value > 0 ? '+' . $value : (string)$value;
};
$direction = function ($delta) {
    if ($delta > 0) {
        return 'd-up';
    }
    return $delta < 0 ? 'd-dn' : 'd-0';
};
// A row's two contributions as two bars on one scale, the larger the longer.
$bars = function (array $row) use ($scale) {
    $out = '';
    foreach (array('was' => $row['before'], 'now' => $row['after']) as $kind => $value) {
        $width = $value === null ? 0 : round(abs($value) / $scale * 100, 1);
        $out .= '<span class="ap-dbar-r is-' . $kind
            . ($value !== null && $value < 0 ? ' is-neg' : '') . '">'
            . '<span style="width:' . $width . '%"></span></span>';
    }
    return '<div class="ap-dbar">' . $out . '</div>';
};
$head = function () {
    return '<thead><tr>'
        . '<th style="width:30%">' . h(__('Signal')) . '</th>'
        . '<th class="wb-wide-only">' . h(__('What it read on this value')) . '</th>'
        . '<th class="r ap-was" style="width:8%">' . h(__('In force')) . '</th>'
        . '<th class="r ap-now" style="width:8%">' . h(__('Candidate')) . '</th>'
        . '<th style="width:14%"></th>'
        . '<th class="r" style="width:9%">' . h(__('Change')) . '</th>'
        . '</tr></thead>';
};
$rowsHtml = function (array $rows) use ($signed, $direction, $bars, $stateLabel) {
    $out = '';
    foreach ($rows as $row) {
        $hot = $row['state'] !== 'same';
        $sub = array_filter(array($row['group'] ?? null, $row['signal'] ?? null));
        $out .= '<tr class="' . ($hot ? 'is-hot' : '') . '">'
            . '<td><div class="wb-id fw-semibold">' . h($row['id']) . '</div>'
            . (empty($sub) ? '' : '<div class="wb-sub">' . h(implode(' · ', $sub)) . '</div>')
            . '</td>'
            . '<td class="wb-wide-only wb-sub">' . h((string)$row['evidence']) . '</td>'
            . '<td class="r num ap-was">' . h($signed($row['before'])) . '</td>'
            . '<td class="r num ap-now">' . h($signed($row['after'])) . '</td>'
            . '<td>' . $bars($row) . '</td>'
            . '<td class="r">' . ($hot
                ? '<span class="ap-delta num ' . $direction($row['delta']) . '">'
                    . h($signed($row['delta'])) . '</span>'
                    . (isset($stateLabel[$row['state']])
                        ? '<div class="wb-sub">' . h($stateLabel[$row['state']]) . '</div>' : '')
                : '<span class="wb-sub">' . h(__('same')) . '</span>')
            . '</td></tr>';
    }
    return $out;
};
$totals = $detail['totals'];
?>
<?php if (empty($detail['rows'])): ?>
    <div class="wb-empty">
        <div class="fw-semibold"><?= h(__('No ledger')) ?></div>
        <p class="mb-0 mt-1"><?= h(__('Neither profile finds anything to'
            . ' weigh on this value, so there is nothing to compare.')) ?></p>
    </div>
<?php else: ?>
    <?php if (empty($moved)): ?>
        <div class="ap-cmp-calm">
            <b><?= h(__('No row moves.')) ?></b>
            <?= h(sprintf(__n(
                'The candidate scores this value exactly as the profile'
                    . ' in force does: %s row, same contribution.',
                'The candidate scores this value exactly as the profile'
                    . ' in force does: %s rows, same contributions.',
                count($detail['rows'])
            ), count($detail['rows']))) ?>
        </div>
    <?php else: ?>
        <table class="wb-tbl ap-cmp-tbl">
            <?= $head() ?>
            <tbody><?= $rowsHtml($moved) ?></tbody>
            <tfoot>
                <tr>
                    <td class="fw-semibold"><?= h(__('Signal strength')) ?></td>
                    <td class="wb-wide-only"></td>
                    <td class="r num ap-was"><?= h($totals['before']) ?></td>
                    <td class="r num ap-now"><?= h($totals['after']) ?></td>
                    <td></td>
                    <td class="r"><span class="ap-delta num <?= h($direction($totals['delta'])) ?>"><?=
                        h($signed($totals['delta'])) ?></span></td>
                </tr>
            </tfoot>
        </table>
    <?php endif; ?>
    <?php if (!empty($still)): ?>
        <details class="ap-cmp-still">
            <summary>
                <i class="fas fa-chevron-right" aria-hidden="true"></i>
                <?= h(sprintf(__n('%s row does not move', '%s rows do not move',
                    count($still)), count($still))) ?>
            </summary>
            <table class="wb-tbl ap-cmp-tbl">
                <?= $head() ?>
                <tbody><?= $rowsHtml($still) ?></tbody>
            </table>
        </details>
    <?php endif; ?>
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
