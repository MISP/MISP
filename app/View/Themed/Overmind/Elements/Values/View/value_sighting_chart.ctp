<?php
/**
 * The Sightings tab's chart: what was reported over time, and what it did
 * to the value's lifetime.
 *
 * The counts first (sightings, false positives, expirations, the lifetime
 * left). Then one bar per day, week or month coloured by kind: sightings
 * above the line, false positives and expirations below it. Under the
 * bars, on the same time axis, a thin band draws the lifetime left, so a
 * refill lines up with the sighting that caused it and a contradiction is
 * seen to refill nothing. The organisations are the Reporters card's.
 *
 * The range buttons pick the span; dragging across the bars narrows the
 * list below to the days dragged over (value-intelligence.js
 * `initSightings`, `misp-brush`).
 *
 * Lazily loaded from ValuesController::viewSightingChart.
 *
 * @var array $valueIntelligence
 * @var bool $showsAssessment
 */
App::uses('ValueIntelligenceBuckets', 'Tools/ValueIntelligence');

$series = $valueIntelligence['sighting_series'];
$sightings = $valueIntelligence['sightings'];
$relevance = $valueIntelligence['relevance'];
$showsAssessment = $showsAssessment ?? true;
$positive = $sightings['total'] - $sightings['fp'] - $sightings['expiration'];
$withLife = $showsAssessment && $relevance['state'] !== null;

$kindLabels = array(
    'sighting' => __('Sightings'),
    'fp' => __('False positives'),
    'expiration' => __('Expirations'),
);

// The span presets, as buttons.
$spanButtons = '';
if ($series !== null && count($series['spans']) > 1) {
    $short = array('90' => __('90 days'), '365' => __('1 year'), 'all' => __('All'));
    $spanButtons = '<div class="vp-seg" role="group" aria-label="' . h(__('Time range')) . '">';
    foreach ($series['spans'] as $span) {
        $on = $span['key'] === $series['default_span'];
        $spanButtons .= '<button type="button" class="vp-seg-btn' . ($on ? ' active' : '') . '"'
            . ' data-vp-sight-span="' . h($span['key']) . '" aria-pressed="' . ($on ? 'true' : 'false') . '"'
            . ' title="' . h($span['label']) . '">'
            . h($short[$span['key']] ?? $span['label']) . '</button>';
    }
    $spanButtons .= '</div>';
}

$subtitle = $sightings['total'] === 0
    ? h(__('Never sighted'))
    : h(sprintf(
        __('%1$s · last one %2$s'),
        __n('%s report', '%s reports', $sightings['total'], number_format($sightings['total'])),
        $sightings['last']
    ));

$payload = null;
if ($series !== null) {
    $payload = array(
        'orgs' => $series['orgs'],
        'plan' => $series['plan'],
        'daily' => $series['daily'],
        'curves' => $withLife ? $series['curves'] : array(),
        'spans' => $series['spans'],
        'default' => $series['default_span'],
        'labels' => array(
            'kinds' => $kindLabels,
            'kindCounted' => array(
                'sighting' => array(__('sighting'), __('sightings')),
                'fp' => array(__('false positive'), __('false positives')),
                'expiration' => array(__('expiration'), __('expirations')),
            ),
            'score' => __('Lifetime left'),
            'perUnit' => array(
                'day' => __('one bar per day'),
                'week' => __('one bar per week'),
                'month' => __('one bar per month'),
            ),
            'perColumn' => ValueIntelligenceBuckets::columnLabels(),
        ),
    );
}

$stat = function ($key, $count, $label) {
    return '<span class="vp-sight-stat' . ($count === 0 ? ' is-zero' : '') . '">'
        . '<i class="vp-sight-dot is-' . h($key) . '" aria-hidden="true"></i>'
        . '<b>' . h(number_format($count)) . '</b>' . h($label) . '</span>';
};
?>
<div class="card shadow-sm mb-3 vp-panel"
     style="--vp-panel-color: var(--sighting);"
     <?= $payload === null ? '' : 'data-vp-sight' ?>>
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('Sightings over time'),
        'panelIcon' => 'misp-icon misp-icon-sighting misp-simple',
        'panelColor' => 'var(--sighting)',
        'panelSub' => $subtitle,
        'panelExtra' => $spanButtons === '' ? null : $spanButtons,
    )) ?>

    <?php if ($series === null): ?>
        <div class="p-3">
            <div class="vp-empty">
                <span class="misp-icon misp-icon-sighting misp-simple"></span>
                <span><?= __('Nobody has reported seeing this.') ?></span>
            </div>
        </div>
    <?php else: ?>
        <div class="vp-sight-stats">
            <?= $stat('sighting', $positive, __n('sighting', 'sightings', $positive)) ?>
            <?= $stat('fp', $sightings['fp'], __n('false positive', 'false positives', $sightings['fp'])) ?>
            <?= $stat('expiration', $sightings['expiration'], __n('expiration', 'expirations', $sightings['expiration'])) ?>
            <?php if ($withLife): ?>
                <span class="vp-sight-stat" title="<?= h(__('The share of the value\'s lifetime still left. A sighting refills it; a false positive or an expiration does not.')) ?>">
                    <i class="vp-sight-dot is-life" aria-hidden="true"></i>
                    <b><?= h(sprintf('%d%%', (int)round($relevance['runway'] * 100))) ?></b>
                    <?= h(sprintf(__('lifetime left · %s-day TTL'), $relevance['ttl']['days'])) ?>
                </span>
            <?php endif; ?>
        </div>

        <div class="vp-sight-body">
            <div class="vp-chart vp-sight-main<?= $withLife ? ' has-life' : '' ?>">
                <canvas id="vp-sight-main" role="img"
                        aria-label="<?= h(__('Reports over time: sightings above the line, false positives and expirations below it, with the lifetime left underneath')) ?>"></canvas>
                <?= $this->element('genericElementsBS5/brush') ?>
                <?php if ($sightings['total'] === 0): ?>
                    <div class="vp-sight-overlay"><?= __('Nobody has reported seeing this.') ?></div>
                <?php endif; ?>
            </div>
            <div class="vp-sight-cap">
                <span class="vp-sight-key"><i class="vp-sight-dot is-sighting" aria-hidden="true"></i><?= __('sightings, above the line') ?></span>
                <?php if ($sightings['fp'] > 0 || $sightings['expiration'] > 0): ?>
                    <span class="vp-sight-key">
                        <?php if ($sightings['fp'] > 0): ?><i class="vp-sight-dot is-fp" aria-hidden="true"></i><?php endif; ?>
                        <?php if ($sightings['expiration'] > 0): ?><i class="vp-sight-dot is-expiration" aria-hidden="true"></i><?php endif; ?>
                        <?= __('contradictions, below') ?>
                    </span>
                <?php endif; ?>
                <?php if ($withLife): ?>
                    <span class="vp-sight-key"><i class="vp-sight-dot is-life" aria-hidden="true"></i><?= __('lifetime left: a sighting refills it') ?></span>
                <?php endif; ?>
                <span class="vp-sight-cap-end">
                    <span data-vp-sight-axis-left><?= __('one bar per day') ?></span>
                    · <?= __('drag across the bars to filter the list') ?>
                </span>
            </div>
        </div>

        <?php if ($withLife && ($sightings['fp'] > 0 || $sightings['expiration'] > 0)): ?>
            <div class="vp-sight-chartnote">
                <i class="fas fa-circle-info" aria-hidden="true"></i>
                <?= __('A false positive or an expiration does not extend the lifetime; only sightings do.') ?>
            </div>
        <?php endif; ?>
        <?php if (!empty($series['clipped'])): ?>
            <div class="vp-sight-chartnote">
                <i class="fas fa-scissors" aria-hidden="true"></i>
                <?= h(sprintf(__('Charted from %1$s; the value was first recorded on %2$s.'), $series['from'], $series['first'])) ?>
            </div>
        <?php endif; ?>

        <script type="application/json" data-vp-sight-data>
            <?= json_encode($payload) ?>
        </script>
    <?php endif; ?>
</div>
