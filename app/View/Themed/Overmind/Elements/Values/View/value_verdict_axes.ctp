<?php
/**
 * The assessment's three axes in one block: the lean as a headline, then
 * the stance, the signal strength and the shelf life as three cells on
 * one grid, so their figures and their glyphs each share a line.
 *
 * The signal strength is printed here and nowhere else in the block.
 *
 * @var array $verdict
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');
App::uses('ValueLeanReasonTool', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$lean = $verdict['lean'] ?? 'none';
$treatment = ValueLean::treatment($lean);
$reason = ValueLeanReasonTool::reasonFor($verdict);
$leanStyle = sprintf(
    '--vp-ax-lean: %s; --vp-ax-lean-ink: %s;',
    $treatment['colour'],
    $treatment['ink']
);

$relevance = isset($verdict['relevance']) && is_array($verdict['relevance'])
    ? $verdict['relevance']
    : array();
$state = $relevance['state'] ?? null;
$tooCommon = ($relevance['reason'] ?? null) === 'rows_not_read';
$noClock = $tooCommon ? __('too common to read') : __('nothing recorded');

$pct = function ($fraction) {
    return max(0, min(100, round((float)$fraction * 100, 2)));
};

/*
 * Each cell as data: the figure, the glyph (a fill and its marks), and
 * the words under it. A cell with no glyph is drawn as absent.
 */
$signalStrength = $verdict['signal_strength'] ?? null;
$band = $verdict['band'] ?? 'none';
if ($band === 'none' || $signalStrength === null) {
    $strength = array(
        'fig' => '<span class="vp-ax-dash">&mdash;</span>',
        'figTitle' => __('Not scored.'),
        'legend' => __('not scored'),
    );
} else {
    $floors = isset($verdict['band_reason']['floors'])
        && is_array($verdict['band_reason']['floors'])
        ? $verdict['band_reason']['floors']
        : array();
    $bandFloors = array(
        'medium' => (int)($floors['medium'] ?? 30),
        'high' => (int)($floors['high'] ?? 60),
    );
    $signed = $signalStrength < 0
        ? "\u{2212}" . abs($signalStrength)
        : (string)$signalStrength;
    $marks = array();
    foreach ($bandFloors as $floorBand => $at) {
        if ($at > 0 && $at < 100) {
            $marks[] = array($at, sprintf(
                __('%1$s starts at %2$s'),
                ucfirst($floorBand),
                $at
            ));
        }
    }
    $strength = array(
        'fig' => '<span class="vp-ax-n">' . h($signed) . '</span>',
        'figTitle' => sprintf(
            __('Signal strength %s of 100: how well documented the record'
                . ' is, not how much of a threat.'),
            $signed
        ),
        'fill' => max(0, min(100, (int)$signalStrength)),
        'marks' => $marks,
        'glyphTitle' => sprintf(
            __('Band %1$s: medium from %2$s, high from %3$s'),
            $band,
            $bandFloors['medium'],
            $bandFloors['high']
        ),
        'legend' => $band,
    );
}
$strength['class'] = 'vp-ax-strength';
$strength['name'] = __('Signal strength');

if ($state === null) {
    $shelf = array(
        'class' => 'vp-ax-shelf',
        'fig' => '<span class="vp-ax-dash">&mdash;</span>',
        'figTitle' => $tooCommon
            ? __('Too common for MISP to read its rows, so no clock runs.')
            : __('Nothing is recorded, so no clock runs.'),
        'legend' => $noClock,
    );
} else {
    $days = $relevance['runway_days'] ?? null;
    $hint = ValueRelevanceTool::stateHint($state);
    if ($days === null) {
        $fig = '<span class="vp-ax-dash">&mdash;</span>';
        $figTitle = null;
    } elseif ($days === 0) {
        $fig = '<span class="vp-ax-n">' . h(__('Today')) . '</span>';
        $figTitle = __('expires today');
    } else {
        $fig = '<span class="vp-ax-n">' . h(abs($days)) . '</span>'
            . '<span class="vp-ax-unit">'
            . h($days > 0 ? __('d left') : __('d over')) . '</span>';
        $figTitle = $days > 0
            ? sprintf(__n('%s day left', '%s days left', $days), $days)
            : sprintf(__n('%s day over', '%s days over', -$days), -$days);
    }
    $ttlDays = $relevance['ttl']['days'] ?? null;
    $glyphTitle = isset($relevance['elapsed_days']) && $ttlDays
        ? sprintf(
            __('%1$s of %2$s days used'),
            $relevance['elapsed_days'],
            $ttlDays
        ) . '. '
        : '';
    $shelf = array(
        'class' => 'vp-ax-shelf vp-ax-shelf-' . $state,
        'fig' => $fig,
        'figTitle' => $figTitle,
        'fill' => $pct($relevance['runway'] ?? 0),
        'marks' => isset($relevance['aging_fraction'])
            ? array(array(
                $pct($relevance['aging_fraction']),
                __('where it stops counting as current'),
            ))
            : array(),
        'glyphTitle' => $glyphTitle . (string)$hint,
        'legend' => ValueRelevanceTool::stateLabel($state),
        'legendClass' => 'vp-ax-state-' . $state,
        'legendTitle' => $hint,
        'notes' => $state !== 'uncertain' && !empty($relevance['uncertain'])
            ? array(array(
                ValueRelevanceTool::stateLabel('uncertain'),
                ValueRelevanceTool::stateHint('uncertain'),
            ))
            : array(),
    );
}
$shelf['name'] = __('Shelf life');

$title = function ($text) {
    return empty($text) ? '' : ' title="' . h($text) . '"';
};
?>
<div class="vp-ax">
    <div class="vp-ax-lean<?= $treatment['definite']
        ? '' : ' vp-ax-lean-quiet' ?>"
         style="<?= h($leanStyle) ?>"<?= $title($reason) ?>>
        <i class="<?= h($treatment['icon']) ?> vp-ax-lean-icon"></i>
        <span class="vp-ax-lean-label"><?= h(ValueLean::label($lean)) ?></span>
        <span class="vp-ax-lean-rule"></span>
    </div>

    <?php if ($lean === 'none'): ?>
        <div class="vp-ax-void">
            <?= h(sprintf(__('No votes · not scored · %s'), $noClock)) ?>
        </div>
    <?php else: ?>
        <div class="vp-ax-cells">
            <?= $this->element('Values/View/value_verdict_stance', array(
                'verdict' => $verdict,
            )) ?>
            <?php foreach (array($strength, $shelf) as $cell):
                $absent = !isset($cell['fill']);
                ?>
                <div class="vp-ax-cell <?= h($cell['class']) ?><?= $absent
                    ? ' vp-ax-absent' : '' ?>">
                    <div class="vp-ax-name"><?= h($cell['name']) ?></div>
                    <div class="vp-ax-fig"<?= $title($cell['figTitle']) ?>>
                        <?= $cell['fig'] ?>
                    </div>
                    <div class="vp-ax-glyph"<?= $absent
                        ? '' : $title($cell['glyphTitle']) ?>>
                        <?php if (!$absent): ?>
                            <span class="vp-ax-track">
                                <span class="vp-ax-fill"
                                      style="width: <?= $cell['fill'] ?>%;"
                                ></span>
                            </span>
                            <?php foreach ($cell['marks'] as $mark): ?>
                                <span class="vp-ax-mark"<?= $title($mark[1]) ?>
                                      style="left: <?= $mark[0] ?>%;"></span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    <div class="vp-ax-read">
                        <div class="vp-ax-legend">
                            <span class="<?= h(trim('vp-ax-word '
                                . ($cell['legendClass'] ?? ''))) ?>"
                                  <?= $title($cell['legendTitle'] ?? null) ?>>
                                <?= h($cell['legend']) ?>
                            </span>
                        </div>
                        <?php if (!empty($cell['notes'])): ?>
                            <div class="vp-ax-notes">
                                <?php foreach ($cell['notes'] as $note): ?>
                                    <span class="vp-ax-note vp-ax-note-unsure"
                                          <?= $title($note[1]) ?>>
                                        <?= h($note[0]) ?>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
