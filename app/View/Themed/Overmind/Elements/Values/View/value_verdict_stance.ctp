<?php
/**
 * The stance: how many organisations take each side, and where the
 * voices sit against the supermajority on either side.
 *
 * One element for both surfaces that draw it — a cell of the Overview
 * card's axes grid, and the Assessment tab's lean band (`stanceWide`) —
 * so the two cannot draw one stance two ways.
 *
 * The figure is a headcount; the bar is the threat share of the voices,
 * which reliability grades, an organisation's own false-positive warning
 * and enrichment modules all weight. The notes say so when they differ.
 *
 * @var array $verdict
 * @var bool $stanceWide The tab's band: figure beside the bar
 */
App::uses('ValueLeanReasonTool', 'Tools/ValueIntelligence');

$stanceWide = !empty($stanceWide);
$stances = isset($verdict['stances']) && is_array($verdict['stances'])
    ? $verdict['stances']
    : array();
$orgs = (int)($stances['orgs'] ?? 0);
$threat = (int)($stances['threat_orgs'] ?? 0);
$benign = (int)($stances['benign_orgs'] ?? 0);
$context = (int)($stances['unflagged_orgs'] ?? 0);
$abstained = isset($stances['abstained']) && is_array($stances['abstained'])
    ? $stances['abstained']
    : array();
$supermajority = isset($stances['supermajority'])
    && is_numeric($stances['supermajority'])
    ? (float)$stances['supermajority']
    : null;
$share = (float)($stances['threat_share'] ?? 0.0);
$sharePct = (int)round($share * 100);
$fillPct = max(0, min(100, round($share * 100, 2)));
$markPct = $supermajority === null
    ? array()
    : array(
        'benign' => round((1 - $supermajority) * 100, 2),
        'threat' => round($supermajority * 100, 2),
    );

$decidedElsewhere = array(
    'escalation' => __('conflict rule decided'),
    'false_positive_floor' => __('warninglist decided'),
    'false_positive_listed' => __('warninglist decided'),
);
$elsewhere = $decidedElsewhere[$verdict['decided_by'] ?? ''] ?? null;

$classes = array('vp-ax-cell', 'vp-ax-stance');
if ($stanceWide) {
    $classes[] = 'vp-ax-stance-wide';
}
if ($elsewhere !== null) {
    $classes[] = 'vp-ax-overruled';
}
if ($orgs === 0) {
    $classes[] = 'vp-ax-absent';
}

$contextTitle = __('Organisations whose occurrences all have to_ids unset:'
    . ' recorded as context, not for detection. No vote either way.');
$threatWords = sprintf(
    __n(
        '%s organisation asserts a threat',
        '%s organisations assert a threat',
        $threat
    ),
    $threat
) . '. ' . __('Organisations with at least one occurrence carrying'
    . ' to_ids.');
$benignWords = sprintf(
    __n('%s reports it as harmless', '%s report it as harmless', $benign),
    $benign
) . '. ' . __('Organisations that filed a false positive, or warned of one'
    . ' on their own report, and do not assert it.');

$notes = array();
if ($elsewhere !== null) {
    $notes[] = array(
        'text' => $elsewhere,
        'class' => 'vp-ax-note-decided',
        'title' => !empty($verdict['rule']['text'])
            ? $verdict['rule']['text']
            : ValueLeanReasonTool::reasonFor($verdict),
    );
}
if ($orgs > 0 && !empty($stances['weighted'])) {
    $notes[] = array(
        'text' => sprintf(__('%s%% by your grades'), $sharePct),
        'class' => 'vp-ax-note-weight',
        'title' => __('The bar is weighted by your reliability grades; the'
            . ' counts above it are headcounts.'),
    );
}
if ($orgs > 0 && !empty($abstained)) {
    $notes[] = array(
        'text' => sprintf(
            __n('%s abstains', '%s abstain', count($abstained)),
            count($abstained)
        ),
        'class' => '',
        'title' => sprintf(
            __('Graded to no voice: %s'),
            implode(', ', $abstained)
        ),
    );
}
if ($context > 0) {
    $notes[] = array(
        'text' => sprintf(
            $orgs > 0 ? __('+%s as context') : __('%s as context'),
            $context
        ),
        'class' => '',
        'title' => $contextTitle,
    );
}

if ($orgs > 0) {
    $glyphTitle = !empty($stances['weighted'])
        ? sprintf(
            __('Weighted by your reliability grades, %1$s for threat and'
                . ' %2$s against: %3$s%% threat.'),
            round((float)($stances['threat_voices'] ?? 0), 2),
            round((float)($stances['benign_voices'] ?? 0), 2),
            $sharePct
        )
        : sprintf(__('Counted as voices: %s%% threat.'), $sharePct);
    if ($supermajority !== null) {
        $glyphTitle .= ' ' . sprintf(
            __('A supermajority is %s%% on either side.'),
            (int)round($supermajority * 100)
        );
    }
}
?>
<?php if ($stanceWide): ?><div class="vp-ax vp-ax-solo"><?php endif; ?>
<div class="<?= h(implode(' ', $classes)) ?>">
    <div class="vp-ax-name"><?= h(__('Stance')) ?></div>
    <?php if ($orgs === 0): ?>
        <div class="vp-ax-fig"
             title="<?= h(__('Nobody flagged it for detection or reported'
                 . ' it as harmless.')) ?>">
            <span class="vp-ax-dash">&mdash;</span>
        </div>
        <div class="vp-ax-glyph"></div>
    <?php else: ?>
        <div class="vp-ax-fig">
            <span class="vp-ax-n vp-ax-t<?= $threat ? '' : ' vp-ax-zero' ?>"
                  title="<?= h($threatWords) ?>"><?= $threat ?></span>
            <span class="vp-ax-colon">:</span>
            <span class="vp-ax-n vp-ax-b<?= $benign ? '' : ' vp-ax-zero' ?>"
                  title="<?= h($benignWords) ?>"><?= $benign ?></span>
        </div>
        <div class="vp-ax-glyph" title="<?= h($glyphTitle) ?>">
            <span class="vp-ax-track vp-ax-tug">
                <span class="vp-ax-fill"
                      style="width: <?= $fillPct ?>%;"></span>
            </span>
            <?php if (!empty($markPct)): ?>
                <?php /* Both marks: a reading between them missed both. */ ?>
                <span class="vp-ax-mark"
                      title="<?= h(__('the benign supermajority')) ?>"
                      style="left: <?= $markPct['benign'] ?>%;"></span>
                <span class="vp-ax-mark"
                      title="<?= h(__('the threat supermajority')) ?>"
                      style="left: <?= $markPct['threat'] ?>%;"></span>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    <div class="vp-ax-read">
        <div class="vp-ax-legend">
            <?php if ($orgs === 0): ?>
                <span class="vp-ax-word"><?= h(__('no votes')) ?></span>
            <?php else: ?>
                <span class="vp-ax-word vp-ax-t"><?= h(__('threat')) ?></span>
                <span class="vp-ax-word vp-ax-b"><?= h(__('harmless')) ?></span>
            <?php endif; ?>
        </div>
        <?php if (!empty($notes)): ?>
            <div class="vp-ax-notes">
                <?php foreach ($notes as $note): ?>
                    <span class="<?= h(trim('vp-ax-note ' . $note['class'])) ?>"
                          <?= empty($note['title'])
                              ? '' : 'title="' . h($note['title']) . '"' ?>>
                        <?= h($note['text']) ?>
                    </span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>
<?php if ($stanceWide): ?></div><?php endif; ?>
