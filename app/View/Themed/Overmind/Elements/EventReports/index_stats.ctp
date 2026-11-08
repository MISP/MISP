<?php
/**
 * How long a report is and how many MISP elements it references, in the
 * reports indexes: two counters in the table, a line of text on the card.
 *
 * Parameters:
 *   digest  array  the row's ctx.digest (Elements/EventReports/index)
 *   long    bool   spell the counts out (default false)
 */
$words = (int)$digest['words'];
$elements = $digest['elements'];
$total = array_sum($elements);
$kinds = [
    'attribute' => function ($n) { return __n('%s attribute', '%s attributes', $n, $n); },
    'object' => function ($n) { return __n('%s object', '%s objects', $n, $n); },
    'tag' => function ($n) { return __n('%s tag', '%s tags', $n, $n); },
    'galaxymatrix' => function ($n) { return __n('%s galaxy matrix', '%s galaxy matrices', $n, $n); },
];
$parts = [];
foreach ($elements as $kind => $n) {
    $parts[] = isset($kinds[$kind]) ? $kinds[$kind]($n) : sprintf('%s %s', $n, $kind);
}
$wordsLabel = __n('%s word', '%s words', $words, number_format($words));
$elementsLabel = __n('%s MISP element', '%s MISP elements', $total, $total);
$elementsTitle = $total === 0
    ? __('No MISP element referenced')
    : __('References %s', implode(', ', $parts));
?>
<?php if (!empty($long)): ?>
    <span class="er-stats-line">
        <span title="<?= h($wordsLabel) ?>"><?= h($wordsLabel) ?></span>
        <?php if ($total > 0): ?>
            <span class="er-stats-sep" aria-hidden="true">·</span>
            <span title="<?= h($elementsTitle) ?>"><?= h($elementsLabel) ?></span>
        <?php endif; ?>
    </span>
<?php else: ?>
    <span class="er-stats">
        <span class="er-stat<?= $words === 0 ? ' is-empty' : '' ?>" title="<?= h($wordsLabel) ?>">
            <i class="fas fa-align-left" aria-hidden="true"></i><?= h(number_format($words)) ?>
        </span>
        <span class="er-stat<?= $total === 0 ? ' is-empty' : '' ?>" title="<?= h($elementsTitle) ?>">
            <i class="fas fa-at" aria-hidden="true"></i><?= (int)$total ?>
        </span>
    </span>
<?php endif; ?>
