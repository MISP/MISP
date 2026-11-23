<?php
/**
 * The Assessment tab's header: the reading and why in one sentence, its
 * provenance on one line, then the three answers it rests on as tiles —
 * the stance, the signal strength with the families that built it, the
 * shelf life with its used and assumed days. Each answer has its own
 * card below, in the same order.
 *
 * Shared by both verdict layouts.
 *
 * @var array $verdict
 */
App::uses('ValueLean', 'Tools/ValueIntelligence');
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');
App::uses('ValueStatsTool', 'Tools/ValueIntelligence');

$lean = $verdict['lean'] ?? 'none';
$treatment = ValueLean::treatment($lean);
$signed = function ($n) {
    $n = (int)$n;
    return $n > 0 ? '+' . $n : ($n < 0 ? "\u{2212}" . abs($n) : "\u{00B1}0");
};

// Stance: the headcount, the threat share of the voices, the rest.
$stances = isset($verdict['stances']) && is_array($verdict['stances']) ? $verdict['stances'] : array();
$voters = (int)($stances['orgs'] ?? 0);
$threat = (int)($stances['threat_orgs'] ?? 0);
$benign = (int)($stances['benign_orgs'] ?? 0);
$context = (int)($stances['unflagged_orgs'] ?? 0);
$share = max(0, min(100, round((float)($stances['threat_share'] ?? 0) * 100, 2)));
$stanceSub = array($voters > 0 ? __('threat : harmless') : __('no votes'));
if ($context > 0) {
    $stanceSub[] = $voters > 0
        ? sprintf(__n('%s more records it as context', '%s more record it as context', $context), $context)
        : sprintf(__n('%s organisation records it as context', '%s organisations record it as context', $context), $context);
}
$decided = array(
    'escalation' => __('a conflict rule decided'),
    'false_positive_floor' => __('a warninglist decided'),
    'false_positive_listed' => __('a warninglist decided'),
);
if (isset($decided[$verdict['decided_by'] ?? ''])) {
    $stanceSub[] = $decided[$verdict['decided_by']];
}
if ($voters > 0 && !empty($stances['weighted'])) {
    $stanceSub[] = sprintf(__('%s%% threat by your grades'), (int)round($share));
}

// Signal strength: the score, its band, and each family's net share of it.
$strength = $verdict['signal_strength'] ?? null;
$band = $verdict['band'] ?? 'none';
$scored = $strength !== null && $band !== 'none';
$families = array();
foreach ($verdict['ledger'] ?? array() as $group) {
    $net = 0;
    foreach ($group['signals'] as $signal) {
        $net += (int)$signal['contribution'];
    }
    $families[] = array('kind' => $group['kind'], 'net' => $net);
}
usort($families, function ($a, $b) {
    return $b['net'] <=> $a['net'];
});
$familyWords = array();
foreach ($families as $family) {
    $familyWords[] = mb_strtolower($family['kind']) . ' ' . $signed($family['net']);
}

// Shelf life: the days left, the days used on the record and assumed.
$relevance = isset($verdict['relevance']) && is_array($verdict['relevance']) ? $verdict['relevance'] : array();
$state = $relevance['state'] ?? null;
$days = $relevance['runway_days'] ?? null;
$ttlDays = (int)($relevance['ttl']['days'] ?? 0);
$assumed = (int)($relevance['assumed_days'] ?? 0);
$usedPct = $ttlDays > 0 ? min(100, round((int)($relevance['recorded_days'] ?? 0) / $ttlDays * 100, 2)) : 0;
$assumedPct = $ttlDays > 0 ? min(100 - $usedPct, round($assumed / $ttlDays * 100, 2)) : 0;
$shelfSub = array();
if ($state !== null) {
    if (!empty($relevance['expired_by'])) {
        $shelfSub[] = sprintf(__('filed as expired by %s'), $relevance['expired_by']['name']);
    } elseif (!empty($relevance['expires_at'])) {
        $shelfSub[] = sprintf(
            $days !== null && $days < 0 ? __('expired %s') : __('expires %s'),
            date('Y-m-d', (int)$relevance['expires_at'])
        );
    }
    if ($state === 'aging') {
        $shelfSub[] = ValueRelevanceTool::stateLabel('aging');
    }
    if ($state === 'uncertain' || !empty($relevance['uncertain'])) {
        $shelfSub[] = $assumed > 0
            ? sprintf(__n('timeline uncertain (%s day assumed)', 'timeline uncertain (%s days assumed)', $assumed), $assumed)
            : ValueRelevanceTool::stateLabel('uncertain');
    }
} else {
    $shelfSub[] = ($relevance['reason'] ?? null) === 'rows_not_read'
        ? __('too common to read')
        : __('nothing recorded');
}
?>
<div class="card shadow-sm mb-3 vp-panel vp-vh vp-vh-<?= h($treatment['slug']) ?>"
     style="--vp-vc-color: <?= h($treatment['colour']) ?>; --vp-vc-ink: <?= h($treatment['ink']) ?>;">
    <div class="vp-vh-main">
        <span class="vp-vc-badge<?= $treatment['definite'] ? '' : ' vp-vc-badge-quiet' ?>">
            <i class="<?= h($treatment['icon']) ?>" aria-hidden="true"></i>
            <?= h(ValueLean::label($lean)) ?>
        </span>
        <?php if (!empty($verdict['summary'])): ?>
            <p class="vp-vh-why"><?= h($verdict['summary']) ?></p>
        <?php endif; ?>
        <?= $this->element('Values/View/value_verdict_meta', array(
            'verdict' => $verdict,
            'metaRule' => $verdict['rule']['text'] ?? null,
        )) ?>
    </div>
    <div class="vp-vh-tiles">
        <div class="vp-vh-tile">
            <span class="vp-vh-k"><?= h(__('Stance')) ?></span>
            <span class="vp-vh-v">
                <?php if ($voters > 0): ?>
                    <span class="<?= $threat > 0 ? 'vp-vh-threat' : '' ?>"><?= h($threat) ?></span>
                    <span class="vp-vh-colon">:</span>
                    <span class="<?= $benign > 0 ? 'vp-vh-benign' : '' ?>"><?= h($benign) ?></span>
                <?php else: ?>
                    &mdash;
                <?php endif; ?>
            </span>
            <span class="vp-vh-bar vp-vh-stance"
                  <?= $voters > 0 ? 'title="' . h(sprintf(__('%s%% of the voices say threat'), (int)round($share))) . '"' : '' ?>>
                <?php if ($voters > 0): ?>
                    <i class="is-threat" style="width: <?= $share ?>%;"></i>
                    <i class="is-benign" style="width: <?= 100 - $share ?>%;"></i>
                <?php endif; ?>
            </span>
            <span class="vp-vh-s"><?= h(implode(' · ', $stanceSub)) ?></span>
        </div>

        <div class="vp-vh-tile">
            <span class="vp-vh-k"><?= h(__('Signal strength')) ?></span>
            <span class="vp-vh-v">
                <?php if ($scored): ?>
                    <?= h((int)$strength < 0 ? "\u{2212}" . abs((int)$strength) : (int)$strength) ?><small>/ 100</small>
                    <span class="vp-band-pill is-<?= h($band) ?>"><?= h($band) ?></span>
                <?php else: ?>
                    &mdash;
                <?php endif; ?>
            </span>
            <span class="vp-vh-bar" title="<?= h(implode(' · ', $familyWords)) ?>">
                <?php if ($scored): ?>
                    <?php foreach ($families as $family): ?>
                        <?php if ($family['net'] > 0): ?>
                            <i style="width: <?= min(100, $family['net']) ?>%; background: <?= h(ValueStatsTool::familyColour($family['kind'])) ?>;"></i>
                        <?php endif; ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            </span>
            <span class="vp-vh-s"><?= h($scored && !empty($familyWords) ? implode(' · ', $familyWords) : __('not scored')) ?></span>
        </div>

        <div class="vp-vh-tile vp-vh-shelf is-<?= h((string)$state) ?>">
            <span class="vp-vh-k"><?= h(__('Shelf life')) ?></span>
            <span class="vp-vh-v">
                <?php if ($state === null || $days === null): ?>
                    &mdash;
                <?php elseif ($days === 0): ?>
                    <?= h(__('Today')) ?><small><?= h(__('expires')) ?></small>
                <?php elseif ($days > 0): ?>
                    <?= h(number_format($days)) ?><small><?= h($ttlDays > 0
                        ? sprintf(__n('day left of %2$s', 'days left of %2$s', $days), $days, number_format($ttlDays))
                        : __n('day left', 'days left', $days)) ?></small>
                <?php else: ?>
                    <?= h(number_format(-$days)) ?><small><?= h(__n('day over', 'days over', -$days)) ?></small>
                <?php endif; ?>
            </span>
            <span class="vp-vh-bar vp-vh-runway"
                  <?= $state === null ? '' : 'title="' . h(sprintf(__('%1$s of %2$s days used'), (int)($relevance['elapsed_days'] ?? 0), $ttlDays)) . '"' ?>>
                <?php if ($state !== null): ?>
                    <i class="is-used" style="width: <?= $usedPct ?>%;"></i>
                    <?php if ($assumedPct > 0): ?>
                        <i class="is-assumed" style="width: <?= $assumedPct ?>%;"></i>
                    <?php endif; ?>
                <?php endif; ?>
            </span>
            <span class="vp-vh-s"><?= h(implode(' · ', $shelfSub)) ?></span>
        </div>
    </div>
</div>
