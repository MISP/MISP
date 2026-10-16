<?php
/**
 * How old the domain was when it was first reported, and who sold it.
 *
 * **The age is the headline and the date is the qualifier**, which is
 * the inverse of how the record states it. A domain registered six
 * days before anybody reported it is the finding; *2026-09-06* is a
 * fact a reader has to do arithmetic on to reach it.
 *
 * The headline is the age **at the first report**, the one the ledger
 * scores; the age today is the sub-line. Without a first report to
 * measure against it falls back to the age today. The tier chip comes
 * from the same reading as the ledger row, and only where the profile
 * scores registration age at all.
 *
 * @var array $data
 */
$record = $data['headline'];
$reading = $record['reading'] ?? null;
$scored = $reading !== null && !$reading['reregistered'];
$tierWords = array(
    RegistrationRenderer::FRESH => array(__('Fresh'), 'mal'),
    RegistrationRenderer::YOUNG => array(__('Young'), 'unknown'),
);
$tier = $scored && $data['thresholds'] !== null
    && isset($tierWords[$reading['tier']])
        ? $tierWords[$reading['tier']]
        : null;
?>
<div class="vp-rw-in vp-rw-reg">
    <?php if ($tier !== null): ?>
        <div class="vp-rw-verdict vp-rw-v-<?= h($tier[1]) ?>"><?=
            h($tier[0]) ?></div>
    <?php endif; ?>
    <?php if ($scored): ?>
        <div class="vp-rw-metric">
            <span class="vp-rw-metric-n"><?=
                h(number_format($reading['age_days'])) ?></span>
            <span class="vp-rw-metric-l"><?= h(__n(
                'day before first report',
                'days before first report',
                $reading['age_days']
            )) ?></span>
        </div>
        <div class="vp-rw-sub"><?= h(date('Y-m-d', $record['created'])) ?>
            <?php if ($record['age_days'] !== null): ?>
                · <?= h(sprintf(
                    __n('%s day old today', '%s days old today',
                        $record['age_days']),
                    number_format($record['age_days'])
                )) ?>
            <?php endif; ?></div>
        <?php if ($reading['match'] === 'parent'): ?>
            <div class="vp-rw-note font-monospace" title="<?=
                h($reading['domain']) ?>"><?= h($reading['domain']) ?></div>
        <?php endif; ?>
    <?php elseif ($record['age_days'] !== null): ?>
        <div class="vp-rw-metric">
            <span class="vp-rw-metric-n"><?=
                h(number_format($record['age_days'])) ?></span>
            <span class="vp-rw-metric-l"><?= h(__n(
                'day old', 'days old', $record['age_days']
            )) ?></span>
        </div>
        <div class="vp-rw-sub"><?= h(date('Y-m-d',
            $record['created'])) ?></div>
    <?php else: ?>
        <div class="vp-rw-head vp-rw-quiet"><?=
            h(__('registered')) ?></div>
    <?php endif; ?>
    <?php if ($reading !== null && $reading['reregistered']): ?>
        <?php
        /*
         * The record is a later registration than the one reported, so
         * its age says nothing about the domain somebody flagged.
         */
        ?>
        <div class="vp-rw-note vp-rw-split" title="<?= h(__(
            'Registered again after MISP first saw it'
        )) ?>"><?= h(__('later registration')) ?></div>
    <?php endif; ?>
    <?php if ($record['registrar'] !== null): ?>
        <div class="vp-rw-note" title="<?=
            h($record['registrar']) ?>"><?= h($record['registrar']) ?></div>
    <?php endif; ?>
    <?php if ($record['expires_in_days'] !== null
        && $record['expires_in_days'] < 30): ?>
        <?php
        /*
         * An expiry inside a month is a finding on its own: a domain
         * about to lapse is about to belong to somebody else.
         */
        ?>
        <div class="vp-rw-note vp-rw-split"><?= h(
            $record['expires_in_days'] < 0
                ? __('expired')
                : sprintf(__('expires in %s days'),
                    $record['expires_in_days'])
        ) ?></div>
    <?php endif; ?>
</div>
