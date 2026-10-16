<?php
/**
 * The registration record, with the raw text last.
 *
 * The nameservers are drawn as a list rather than a line because they
 * are a pivot: two unrelated domains on one pair of nameservers is
 * exactly the kind of link this page exists to surface.
 *
 * The raw text goes at the bottom and is not hidden. A widget built on
 * a parse has to show what it parsed, and a reader who disagrees with
 * a field has nowhere else to check it.
 *
 * The age that scores is the one **at the first report**, and each
 * record states it beside the age today, with the tier the profile's
 * thresholds give it — the same reading the ledger row is built from.
 *
 * @var array $data
 */
$tierWords = array(
    RegistrationRenderer::FRESH => array(__('Fresh'), 'mal'),
    RegistrationRenderer::YOUNG => array(__('Young'), 'unknown'),
);
?>
<div class="vp-rf vp-rf-reg">
    <?php if ($data['thresholds'] !== null): ?>
        <div class="vp-rf-sub"><?= h(sprintf(
            __('Your profile reads a domain registered at most %1$s days'
                . ' before its first report as fresh, and at most %2$s'
                . ' days as young.'),
            $data['thresholds']['fresh_days'],
            $data['thresholds']['young_days']
        )) ?></div>
    <?php endif; ?>
    <?php foreach ($data['records'] as $record): ?>
        <?php
        $reading = $record['reading'] ?? null;
        $scored = $reading !== null && !$reading['reregistered'];
        $tier = $scored && $data['thresholds'] !== null
            && isset($tierWords[$reading['tier']])
                ? $tierWords[$reading['tier']]
                : null;
        ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($record['domain'] !== null): ?>
                    <span class="vp-rf-key font-monospace"><?=
                        h($record['domain']) ?></span>
                <?php endif; ?>
                <?php if ($scored): ?>
                    <span class="vp-rf-name"><?= h(sprintf(
                        __n('%s day before first report',
                            '%s days before first report',
                            $reading['age_days']),
                        number_format($reading['age_days'])
                    )) ?></span>
                <?php elseif ($record['age_days'] !== null): ?>
                    <span class="vp-rf-name"><?= h(sprintf(
                        __n('%s day old', '%s days old',
                            $record['age_days']),
                        number_format($record['age_days'])
                    )) ?></span>
                <?php endif; ?>
                <?php if ($tier !== null): ?>
                    <span class="vp-rw-verdict vp-rw-v-<?=
                        h($tier[1]) ?>"><?= h($tier[0]) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $record['module'])
                    ) ?></span>
            </div>
            <?php if ($reading !== null && $reading['reregistered']): ?>
                <div class="vp-rf-sub vp-rw-split"><?= h(__(
                    'Registered again after MISP first saw it, so this'
                    . ' record describes a later registration than the'
                    . ' one reported.'
                )) ?></div>
            <?php endif; ?>
            <dl class="vp-rf-pairs">
                <?php if ($record['created'] !== null): ?>
                    <dt><?= h(__('Registered')) ?></dt>
                    <dd><?= h(date('Y-m-d', $record['created'])) ?></dd>
                <?php endif; ?>
                <?php if ($reading !== null): ?>
                    <dt><?= h(__('First reported')) ?></dt>
                    <dd><?= h(date('Y-m-d', $reading['first_report'])) ?></dd>
                <?php endif; ?>
                <?php if ($scored && $record['age_days'] !== null): ?>
                    <dt><?= h(__('Age today')) ?></dt>
                    <dd><?= h(sprintf(
                        __n('%s day', '%s days', $record['age_days']),
                        number_format($record['age_days'])
                    )) ?></dd>
                <?php endif; ?>
                <?php if ($record['modified'] !== null): ?>
                    <dt><?= h(__('Last changed')) ?></dt>
                    <dd><?= h(date('Y-m-d', $record['modified'])) ?></dd>
                <?php endif; ?>
                <?php if ($record['expires'] !== null): ?>
                    <dt><?= h(__('Expires')) ?></dt>
                    <dd><?= h(date('Y-m-d', $record['expires'])) ?></dd>
                <?php endif; ?>
                <?php if ($record['registrar'] !== null): ?>
                    <dt><?= h(__('Registrar')) ?></dt>
                    <dd><?= h($record['registrar']) ?></dd>
                <?php endif; ?>
                <?php foreach ($record['registrant'] as $k => $v): ?>
                    <dt><?= h($k) ?></dt>
                    <dd><?= h($v) ?></dd>
                <?php endforeach; ?>
            </dl>
            <?php if (!empty($record['nameservers'])): ?>
                <div class="vp-rf-sub"><?=
                    h(__('Nameservers')) ?></div>
                <ul class="vp-rf-prefixes">
                    <?php foreach ($record['nameservers'] as $ns): ?>
                        <li class="font-monospace"><?= h($ns) ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
            <?php if ($record['text'] !== null): ?>
                <details class="vp-rf-raw">
                    <summary><?= h(__('Raw record')) ?></summary>
                    <pre><?= h($record['text']) ?></pre>
                </details>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
