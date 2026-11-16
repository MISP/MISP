<?php
/**
 * The Collaboration tab's top card: where the organisations stand on this
 * value.
 *
 * A 0 to 100 ruler with MISP's five opinion bands, each opinion drawn as
 * its organisation's tile at its score, so groups and the empty stretch
 * show by themselves; the average sits under the ruler. Then the opinions
 * as a list: organisation, score and band, the side it takes, the
 * organisation's notes and last activity. The header counts the opinions
 * on each side. A notes count narrows Notes and opinions, further down
 * the tab, to that organisation's notes.
 *
 * Above 50 agrees with what the value asserts, below 50 disputes it. An
 * opinion is one row: an organisation holding two opinions has two. An
 * opinion written on a note rates the note and is not counted here.
 *
 * No opinion, no card. Lazily loaded from
 * ValuesController::viewAnalystStanding.
 *
 * @var array $valueIntelligence
 */
$standing = $valueIntelligence['analyst']['standing'];
$aggregate = $standing['aggregate'];
if ($aggregate === null) {
    return;
}
$opinions = $standing['orgs'];

$sideOf = function ($reads) {
    if ($reads === 'malicious') {
        return 'agree';
    }
    if ($reads === 'benign') {
        return 'dispute';
    }
    return 'neither';
};
$sideWords = array(
    'agree' => __('agrees'),
    'dispute' => __('disputes'),
    'neither' => __('takes no side'),
);

$bySide = array('agree' => 0, 'neither' => 0, 'dispute' => 0);
$orgCount = array();
foreach ($opinions as $opinion) {
    $bySide[$sideOf($opinion['reads'])]++;
    $orgCount[$opinion['org']] = true;
}

// Markers closer than this many points stack on the next lane down.
$crowd = 6;
$byScore = $opinions;
usort($byScore, function ($a, $b) {
    return (int)$a['score'] - (int)$b['score'];
});
$placed = array();
foreach ($byScore as $opinion) {
    $lane = 0;
    $taken = function ($lane) use ($placed, $opinion, $crowd) {
        foreach ($placed as $other) {
            if ($other['lane'] === $lane && abs((int)$other['score'] - (int)$opinion['score']) < $crowd) {
                return true;
            }
        }
        return false;
    };
    while ($taken($lane)) {
        $lane++;
    }
    $placed[] = $opinion + array('lane' => $lane);
}
$lanes = max(array_column($placed, 'lane')) + 1;

$gap = $aggregate['gap'];
$showGap = $gap !== null && $gap['points'] >= 20;
$mean = (float)$aggregate['mean'];
$orphan = !empty($aggregate['mean_orphan']);

// An organisation silent this long is marked in the list.
$staleAfter = 60;
$ageLabel = function ($days) {
    if ($days <= 0) {
        return __('today');
    }
    if ($days === 1) {
        return __('yesterday');
    }
    if ($days < 31) {
        return sprintf(__n('%d day ago', '%d days ago', $days), $days);
    }
    $months = max(1, (int)round($days / 30.44));
    return sprintf(__n('%d month ago', '%d months ago', $months), $months);
};

$bands = array(
    __('Strongly disagree'),
    __('Disagree'),
    __('Neutral'),
    __('Agree'),
    __('Strongly agree'),
);

$pills = '';
foreach (array(
    'agree' => __n('%s agrees', '%s agree', $bySide['agree']),
    'neither' => __('%s no side'),
    'dispute' => __n('%s disputes', '%s dispute', $bySide['dispute']),
) as $side => $label) {
    if ($bySide[$side] === 0) {
        continue;
    }
    $pills .= '<span class="vps-pill vpa-s-' . $side . '"><i aria-hidden="true"></i>'
        . h(sprintf($label, $bySide[$side])) . '</span>';
}
$pills .= '<span class="vps-pill vps-pill-avg" title="' . h($orphan
        ? __('Average of the opinions. No opinion sits near it: the set is divided.')
        : __('Average of the opinions.')) . '">'
    . h(sprintf(__('avg %s'), $aggregate['mean_label']))
    . ($orphan ? '<small>' . h(__('nobody near it')) . '</small>' : '')
    . '</span>';

$subtitle = h(sprintf(
    __('%1$s from %2$s'),
    sprintf(__n('%s opinion', '%s opinions', count($opinions)), count($opinions)),
    sprintf(__n('%s organisation', '%s organisations', count($orgCount)), count($orgCount))
));

$list = $opinions;
usort($list, function ($a, $b) {
    return (int)$b['score'] - (int)$a['score'];
});
?>
<div class="card shadow-sm mb-3 vp-panel vps-card" style="--vp-panel-color: var(--analystData);" data-vp-analyst-standing>

    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Where the organisations stand'),
        'panelIcon' => 'fas fa-arrows-left-right-to-line',
        'panelColor' => 'var(--analystData)',
        'panelSub' => $subtitle,
        'panelExtra' => '<div class="vps-pills">' . $pills . '</div>',
    )) ?>

    <div class="vps-scale">
        <div class="vps-plot" style="--vps-lanes: <?= (int)$lanes ?>;" role="img"
             aria-label="<?= h(implode(__(', '), array_map(function ($opinion) {
                 return sprintf(__('%1$s at %2$s'), $opinion['org'], $opinion['score']);
             }, $list))) ?>">
            <div class="vps-markers">
                <?php foreach ($placed as $opinion): ?>
                    <?php $side = $sideOf($opinion['reads']); ?>
                    <span class="vps-marker vpa-s-<?= $side ?>"
                          style="left: <?= (int)$opinion['score'] ?>%; --vps-lane: <?= (int)$opinion['lane'] ?>;"
                          title="<?= h(sprintf(__('%1$s · %2$s/100 · %3$s'), $opinion['org'], $opinion['score'], $opinion['label'])) ?>">
                        <span class="vps-marker-score"><?= (int)$opinion['score'] ?></span>
                        <?= $this->EventIndex->orgTile(array('id' => $opinion['org_id'], 'name' => $opinion['org']), 22) ?>
                        <span class="vps-marker-stem"></span>
                    </span>
                <?php endforeach; ?>
                <?php if ($showGap): ?>
                    <span class="vps-gap-label" style="left: <?= ($gap['from'] + $gap['to']) / 2 ?>%;"><?= h(sprintf(
                        __('no opinion between %1$s and %2$s'),
                        $gap['from'],
                        $gap['to']
                    )) ?></span>
                <?php endif; ?>
            </div>
            <div class="vps-track">
                <?php foreach ($bands as $i => $band): ?>
                    <span class="vps-zone vps-zone-<?= $i ?>"></span>
                <?php endforeach; ?>
                <?php if ($showGap): ?>
                    <span class="vps-gap" style="left: <?= $gap['from'] ?>%; width: <?= $gap['to'] - $gap['from'] ?>%;"></span>
                <?php endif; ?>
            </div>
            <div class="vps-bands">
                <?php foreach ($bands as $band): ?>
                    <span><?= h($band) ?></span>
                <?php endforeach; ?>
            </div>
            <div class="vps-avg-row">
                <span class="vps-avg" style="left: <?= round($mean, 1) ?>%;"><?= h(sprintf(__('avg %s'), $aggregate['mean_label'])) ?></span>
            </div>
        </div>
    </div>

    <div class="vps-list">
        <div class="vps-row vps-row-head">
            <span><?= __('Organisation') ?></span>
            <span><?= __('Opinion') ?></span>
            <span class="vps-r"><?= __('Notes') ?></span>
            <span class="vps-r"><?= __('Last activity') ?></span>
        </div>
        <?php foreach ($list as $opinion): ?>
            <?php
            $side = $sideOf($opinion['reads']);
            $days = isset($opinion['days']) ? $opinion['days'] : null;
            $stale = $days !== null && $days >= $staleAfter;
            ?>
            <div class="vps-row">
                <span class="vps-org">
                    <?= $this->element('Values/View/value_org_link', array(
                        'org' => array('id' => $opinion['org_id'], 'name' => $opinion['org']),
                    )) ?>
                </span>
                <span class="vps-opinion">
                    <span class="vps-score vpa-s-<?= $side ?>"><i aria-hidden="true"></i><?= (int)$opinion['score'] ?></span>
                    <span class="vps-band"><?= h($opinion['label']) ?> · <?= h($sideWords[$side]) ?></span>
                </span>
                <span class="vps-r">
                    <?php if ($opinion['notes'] > 0): ?>
                        <button type="button" class="vps-notes" data-vp-ad-org-notes="<?= h($opinion['org']) ?>"
                                title="<?= h(sprintf(__n('Show the note by %2$s in Notes and opinions', 'Show the %1$s notes by %2$s in Notes and opinions', $opinion['notes']), $opinion['notes'], $opinion['org'])) ?>">
                            <i class="misp-icon misp-icon-analyst-note misp-simple"></i><?= (int)$opinion['notes'] ?>
                        </button>
                    <?php else: ?>
                        <span class="text-body-secondary">&mdash;</span>
                    <?php endif; ?>
                </span>
                <span class="vps-r">
                    <span class="vps-age<?= $stale ? ' is-stale' : '' ?>" title="<?= h($stale
                        ? sprintf(__('%s. Nothing from this organisation for over %d days.'), $opinion['last'], $staleAfter)
                        : $opinion['last']) ?>"><?= h($days === null ? $opinion['last'] : $ageLabel($days)) ?></span>
                </span>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="vp-acl-note">
        <i class="fas fa-user-shield" aria-hidden="true"></i>
        <span><?= h(__('Computed over the opinions you can see: another reader may see other ones.')) ?></span>
    </div>
</div>
