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
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-reg">
    <?php foreach ($data['records'] as $record): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($record['domain'] !== null): ?>
                    <span class="vp-rf-key font-monospace"><?=
                        h($record['domain']) ?></span>
                <?php endif; ?>
                <?php if ($record['age_days'] !== null): ?>
                    <span class="vp-rf-name"><?= h(sprintf(
                        __n('%s day old', '%s days old',
                            $record['age_days']),
                        number_format($record['age_days'])
                    )) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $record['module'])
                    ) ?></span>
            </div>
            <dl class="vp-rf-pairs">
                <?php if ($record['created'] !== null): ?>
                    <dt><?= h(__('Registered')) ?></dt>
                    <dd><?= h(date('Y-m-d', $record['created'])) ?></dd>
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
