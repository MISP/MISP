<?php
/**
 * The Assessment tab's stance card: who says it, and how the reading was
 * decided. The rule in one sentence, then one row per reporting
 * organisation with its stance, its occurrences and what else it said
 * (opinion, sightings, false positives, reliability). Under them, what
 * else argued the reading, a conflict rule that did not run, and where the
 * record disagrees with itself.
 *
 * Shared by both verdict layouts.
 *
 * @var array $verdict
 */
App::uses('ValueLeanReasonTool', 'Tools/ValueIntelligence');
App::uses('ValueTrustTool', 'Tools/ValueIntelligence');

$lean = $verdict['lean'] ?? 'none';
$stances = isset($verdict['stances']) && is_array($verdict['stances']) ? $verdict['stances'] : array();
$orgs = $verdict['orgs'] ?? array();
$reason = ValueLeanReasonTool::reasonFor($verdict);
$exit = ValueLeanReasonTool::exitFor($verdict);
$leanRows = isset($verdict['lean_ledger']) && is_array($verdict['lean_ledger']) ? $verdict['lean_ledger'] : array();
$errors = isset($verdict['rule_errors']) && is_array($verdict['rule_errors']) ? $verdict['rule_errors'] : array();
$conflicts = $verdict['conflicts'] ?? array();
$warninglist = $verdict['warninglist'] ?? null;

if (empty($orgs) && $reason === null && empty($leanRows) && $warninglist === null) {
    return;
}

$titles = array(
    'threat' => __('Who says it is a threat'),
    'benign' => __('Who says it is harmless'),
    'contested' => __('Who says what'),
);
$title = $titles[$lean] ?? __('Who reported it');
$voters = (int)($stances['orgs'] ?? 0);
$figure = $voters > 0
    ? (int)($stances['threat_orgs'] ?? 0) . ' : ' . (int)($stances['benign_orgs'] ?? 0)
    : null;

/**
 * An organisation's stance, from its occurrences' to_ids and its false
 * positives: [slug, words, title].
 *
 * @param array $org
 * @return array
 */
$stanceOf = function (array $org) {
    if ($org['to_ids'] === 'mixed') {
        return array('both', "\u{25C6} " . __('both ways'),
            __('Some of its occurrences are flagged for detection and some are not. It counts as asserting a threat.'));
    }
    if ($org['to_ids'] === 'yes') {
        return array('threat', "\u{25B2} " . __('flags it for detection'),
            __('At least one of its occurrences carries to_ids.'));
    }
    if ((int)$org['fp'] > 0) {
        return array('benign', "\u{25BC} " . __('files it as harmless'),
            __('It filed a false positive and does not flag it for detection.'));
    }
    return array('context', __('records it as context'),
        __('None of its occurrences carries to_ids: no vote either way.'));
};

/**
 * What else an organisation said about the value, in a few words.
 *
 * @param array $org
 * @return array
 */
$saidOf = function (array $org) {
    $said = array();
    if ($org['opinion'] !== null) {
        $said[] = sprintf(__('opinion %s'), $org['opinion']);
    }
    if ((int)$org['sightings'] > 0) {
        $said[] = sprintf(__n('%s sighting', '%s sightings', (int)$org['sightings']), number_format((int)$org['sightings']));
    }
    if ((int)$org['fp'] > 0) {
        $said[] = sprintf(__n('%s false positive', '%s false positives', (int)$org['fp']), number_format((int)$org['fp']));
    }
    if ($org['reliability'] !== ValueTrustTool::UNRATED) {
        $said[] = sprintf(__('reliability %s'), $org['reliability']);
    }
    return $said;
};

$leanBenign = $lean === 'benign';
$leanWeight = (int)($verdict['lean_weight'] ?? 0);
?>
<div class="card shadow-sm mb-3 vp-panel vp-vv" style="--vp-panel-color: var(--vp-vc-color, var(--object));">
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => $title,
        'panelIcon' => 'fas fa-scale-balanced',
        'panelColor' => 'var(--object)',
        'panelSub' => $exit === null ? null
            : '<span title="' . h((string)$reason) . '">' . h($exit) . '</span>',
        'panelExtra' => $figure === null ? null
            : '<span class="vp-card-figure" title="' . h(__('Organisations asserting a threat : organisations reporting it as harmless')) . '">'
                . h($figure) . '</span>',
    )) ?>

    <?php if ($warninglist !== null): ?>
        <?= $this->element('Values/View/value_verdict_warninglist', array('warninglist' => $warninglist)) ?>
    <?php endif; ?>

    <?php if (!empty($orgs)): ?>
        <div class="table-responsive">
            <table class="table align-middle mb-0 ix-table vp-vv-table">
                <thead>
                    <tr>
                        <th><?= __('Organisation') ?></th>
                        <th><?= __('Stance') ?></th>
                        <th><?= __('Occurrences') ?></th>
                        <th><?= __('Opinion · sightings · FP') ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($orgs as $org): ?>
                        <?php
                        list($slug, $words, $why) = $stanceOf($org);
                        $said = $saidOf($org);
                        ?>
                        <tr>
                            <td><span class="vp-grade">
                                <?= $this->element('Values/View/value_org_link', array(
                                    'org' => array('id' => $org['org_id'] ?? null, 'name' => $org['org']),
                                )) ?>
                                <?= $this->OrgGrade->badge(
                                    array('id' => $org['org_id'] ?? 0, 'uuid' => $org['org_uuid'] ?? '', 'name' => $org['org']),
                                    $orgGrading ?? null,
                                    'square'
                                ) ?>
                            </span></td>
                            <td><span class="vp-vv-stance is-<?= h($slug) ?>" title="<?= h($why) ?>"><?= h($words) ?></span></td>
                            <td class="vp-vv-n"><?= h(number_format((int)$org['occurrences'])) ?></td>
                            <td class="vp-vv-said<?= empty($said) ? ' is-none' : '' ?>"><?= empty($said) ? '&mdash;' : h(implode(' · ', $said)) ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>

    <?php if (!empty($leanRows)): ?>
        <div class="vp-vv-section">
            <div class="vp-vv-section-h">
                <?= h(__('What else argued the reading')) ?>
                <span class="vp-vv-section-n" title="<?= h(__('Not part of the signal strength.')) ?>"><?= h(($leanWeight > 0 ? '+' : '') . $leanWeight) ?></span>
            </div>
            <?php foreach ($leanRows as $row): ?>
                <?php
                $points = (int)$row['contribution'];
                $argues = ($points >= 0) !== $leanBenign ? 'threat' : 'harmless';
                ?>
                <div class="vp-vv-line">
                    <span class="vp-pts is-<?= $argues === 'threat' ? 'down' : 'up' ?>"
                          title="<?= h($argues === 'threat' ? __('Argues threat') : __('Argues harmless')) ?>"><?= h(($points > 0 ? '+' : '') . $points) ?></span>
                    <span><span class="vp-vv-line-t"><?= h($row['signal']) ?></span>
                        <span class="vp-vv-line-e"><?= h($row['evidence']) ?></span></span>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
        <div class="vp-vv-errors">
            <i class="fas fa-triangle-exclamation" aria-hidden="true"></i>
            <span>
                <?= h(__n('A conflict rule this profile enables did not run:', 'Conflict rules this profile enables did not run:', count($errors))) ?>
                <?php foreach ($errors as $error): ?>
                    <span class="font-monospace"><?= h($error['id']) ?></span> <?= h($error['note']) ?>
                <?php endforeach; ?>
            </span>
        </div>
    <?php endif; ?>

    <?php foreach ($conflicts as $conflict): ?>
        <div class="vp-vv-conflict">
            <span class="vp-vv-conflict-mark" aria-hidden="true">&#9670;</span>
            <span><strong><?= h($conflict['title']) ?></strong> — <?= h($conflict['evidence'] ?? $conflict['note']) ?>
                <span class="vp-vv-conflict-note"><?= h(__('No points; it is why the reading could tip.')) ?></span></span>
        </div>
    <?php endforeach; ?>
</div>
