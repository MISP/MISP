<?php
/**
 * The Assessment tab's shelf life card: how long this reading holds. The
 * runway from the clock to the expiry (days used on the record, days
 * assumed), the date at each end, a note for each assumption the clock
 * makes, and the confirmations that reset it. It affects neither the lean
 * nor the signal strength. The Sightings tab's Lifetime card draws the
 * same block in full (value_relevance_facts).
 *
 * Shared by both verdict layouts.
 *
 * @var array $verdict
 */
App::uses('ValueRelevanceTool', 'Tools/ValueIntelligence');

$relevance = $verdict['relevance'] ?? array();
$state = $relevance['state'] ?? null;
if (($verdict['lean'] ?? null) === 'none' && $state === null) {
    return;
}
$clock = $relevance['clock'] ?? array();
$ttl = $relevance['ttl'] ?? array();
$ttlDays = (int)($ttl['days'] ?? 0);
$days = $relevance['runway_days'] ?? null;
$assumed = (int)($relevance['assumed_days'] ?? 0);

$figure = null;
if ($state !== null && $days !== null) {
    $figure = $days === 0
        ? __('expires today')
        : ($days > 0
            ? sprintf(__n('%s day left', '%s days left', $days), number_format($days))
            : sprintf(__n('%s day over', '%s days over', -$days), number_format(-$days)));
}

// The sub-title: where the lifetime comes from, and from when it runs.
$sub = array();
$subTitle = null;
if ($state !== null) {
    $buckets = array(
        'short' => __('short lifetime'),
        'medium' => __('medium lifetime'),
        'long' => __('long lifetime'),
        'very_long' => __('very long lifetime'),
    );
    if (!empty($ttl['type'])) {
        $sub[] = $ttl['type'];
    }
    if (($ttl['from'] ?? null) === 'bucket' && isset($buckets[$ttl['bucket'] ?? ''])) {
        $sub[] = $buckets[$ttl['bucket']];
    } elseif (($ttl['from'] ?? null) === 'override') {
        $sub[] = __('its own lifetime override');
    } else {
        $sub[] = __('the profile\'s default lifetime');
    }
    if (!empty($ttl['spread']) && !empty($ttl['candidates'])) {
        $rules = array(
            'shortest' => __('the shortest of its %s types'),
            'longest' => __('the longest of its %s types'),
            'most_common' => __('the most common of its %s types'),
        );
        $sub[] = sprintf($rules[$ttl['rule'] ?? ''] ?? __('one of its %s types'), count($ttl['candidates']));
        $each = array();
        foreach ($ttl['candidates'] as $candidate) {
            $each[] = sprintf(__('%1$s: %2$s days'), $candidate['type'], $candidate['days']);
        }
        $subTitle = implode(' · ', $each);
    }
    if ($ttlDays > 0) {
        $sub[] = !empty($clock['fallback'])
            ? sprintf(__('%s days from when it was last added'), number_format($ttlDays))
            : sprintf(__('%s days from the last confirmation'), number_format($ttlDays));
    }
}

// The runway: days used on the record, then the assumed ones.
$usedPct = $ttlDays > 0 ? min(100, round((int)($relevance['recorded_days'] ?? 0) / $ttlDays * 100, 2)) : 0;
$assumedPct = $ttlDays > 0 ? min(100 - $usedPct, round($assumed / $ttlDays * 100, 2)) : 0;

// What resets the clock, newest first: the one holding it in full.
$events = array_reverse($clock['events'] ?? array());
$cap = 4;
$shown = array_slice($events, 0, $cap);
?>
<div class="card shadow-sm mb-3 vp-panel vp-vt vp-vt-<?= h((string)$state) ?>" style="--vp-panel-color: var(--correlation);">
    <?= $this->element('Values/View/value_panel_header', array(
        'panelTitle' => __('How long it holds'),
        'panelIcon' => 'fas fa-hourglass-half',
        'panelColor' => 'var(--correlation)',
        'panelSub' => empty($sub) ? null
            : '<span' . ($subTitle === null ? '' : ' title="' . h($subTitle) . '"') . '>' . h(implode(' · ', $sub)) . '</span>',
        'panelExtra' => $figure === null ? null : '<span class="vp-card-figure">' . h($figure) . '</span>',
    )) ?>
    <div class="vp-vt-body">
        <?php if ($state === null): ?>
            <?= $this->element('Values/View/value_relevance_facts', array('relevance' => $relevance)) ?>
        <?php else: ?>
            <div class="vp-vt-runway" title="<?= h($assumed > 0
                ? sprintf(__('%1$s of %2$s days used: %3$s on the record, %4$s assumed'),
                    (int)($relevance['elapsed_days'] ?? 0), $ttlDays, (int)($relevance['recorded_days'] ?? 0), $assumed)
                : sprintf(__('%1$s of %2$s days used'), (int)($relevance['elapsed_days'] ?? 0), $ttlDays)) ?>">
                <i class="is-used" style="width: <?= $usedPct ?>%;"></i>
                <?php if ($assumedPct > 0): ?>
                    <i class="is-assumed" style="width: <?= $assumedPct ?>%;"></i>
                <?php endif; ?>
            </div>
            <div class="vp-vt-ends">
                <span title="<?= h(sprintf(__('This profile resets the clock on the %s.'), ValueRelevanceTool::clockLabel($clock['setting'] ?? null))) ?>">
                    <?= h(sprintf(
                        !empty($clock['fallback']) ? __('added %1$s by %2$s') : __('confirmed %1$s by %2$s'),
                        date('Y-m-d', (int)$clock['at']),
                        $clock['by'] ?? __('an unnamed organisation')
                    )) ?>
                </span>
                <span>
                    <?php if (!empty($relevance['expired_by'])): ?>
                        <?= h(sprintf(__('filed as expired by %1$s on %2$s'),
                            $relevance['expired_by']['name'], date('Y-m-d', (int)$relevance['expired_by']['at']))) ?>
                    <?php else: ?>
                        <?= h(sprintf($days !== null && $days < 0 ? __('expired %s') : __('expires %s'),
                            date('Y-m-d', (int)$relevance['expires_at']))) ?>
                    <?php endif; ?>
                </span>
            </div>

            <?php if (!empty($relevance['uncertain'])): ?>
                <div class="vp-vt-note">
                    <?php if ($assumed > 0): ?>
                        <strong><?= h(sprintf(__n('%s day assumed.', '%s days assumed.', $assumed), $assumed)) ?></strong>
                        <?= h(sprintf(
                            __n('No occurrence says when this value was first seen, only when it was recorded, so it is counted as %s day older than its record.',
                                'No occurrence says when this value was first seen, only when it was recorded, so it is counted as %s days older than its record.',
                                $assumed),
                            $assumed
                        )) ?>
                        <?= h(__('It ages the value sooner; it never moves the expiry.')) ?>
                        <?php if (!empty($relevance['assumed_capped'])): ?>
                            <?= h(sprintf(__('The profile would have assumed %s days; the rest is not applied, because an assumption may never expire a value on its own.'),
                                $relevance['assumed_setting'])) ?>
                        <?php endif; ?>
                    <?php else: ?>
                        <strong><?= h(__('Timeline uncertain.')) ?></strong>
                        <?= h(__('No occurrence says when this value was first seen, only when it was recorded: it may be older than shown.')) ?>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            <?php if (!empty($clock['fallback'])): ?>
                <div class="vp-vt-note" title="<?= h(__('One organisation reporting a value is the claim, not its confirmation.')) ?>">
                    <strong><?= h(__('Not confirmed yet.')) ?></strong>
                    <?= h(__('Nobody else has confirmed this value, so the clock runs from the day it was last added.')) ?>
                </div>
            <?php endif; ?>
            <?php if (empty($clock['rows_read'])): ?>
                <div class="vp-vt-note" title="<?= h(__('MISP stops correlating a value that appears in too many events.')) ?>">
                    <strong><?= h(__('Not every report was read.')) ?></strong>
                    <?= h(__('This value is too common for MISP to correlate, so a sighting could be newer than the date shown.')) ?>
                </div>
            <?php endif; ?>

            <?php if (!empty($shown)): ?>
                <div class="vp-vt-resets">
                    <span class="vp-vt-resets-k"><?= h(__('Reset by')) ?></span>
                    <?php $lastDate = null; ?>
                    <?php foreach ($shown as $i => $event): ?>
                        <?php
                        $date = date('Y-m-d', (int)$event['at']);
                        $who = empty($event['by']) ? __('unnamed') : $event['by'];
                        $kind = ValueRelevanceTool::kindLabel($event['kind']);
                        $hint = ValueRelevanceTool::kindHint($event['kind']);
                        if ($i === 0) {
                            $words = $date . ' · ' . $who . ' · ' . $kind;
                        } else {
                            $words = $date === $lastDate ? $who : $date . ' · ' . $who;
                        }
                        $lastDate = $date;
                        ?>
                        <span class="vp-vt-chip<?= $i === 0 ? ' is-held' : '' ?>"
                              title="<?= h($date . ' · ' . $who . ' · ' . $kind . ($hint === null ? '' : ' — ' . $hint)) ?>"><?= h($words) ?></span>
                    <?php endforeach; ?>
                    <?php if (count($events) > count($shown)): ?>
                        <span class="vp-vt-chip is-more"><?= h(sprintf(__('+%s earlier'), count($events) - count($shown))) ?></span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</div>
