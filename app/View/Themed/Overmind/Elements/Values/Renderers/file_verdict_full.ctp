<?php
/**
 * Each service's report, with the dates that make a ratio mean
 * something.
 *
 * **The submission dates are the half of this the compact form cannot
 * carry.** A 54/72 on a file first submitted four years ago and a
 * 54/72 on one first submitted this morning are different findings,
 * and the second is the one worth acting on now.
 *
 * Per-engine results are not drawn: the object templates carry a
 * ratio and not a breakdown, so there is nothing here to draw them
 * from, and the permalink is where that detail lives.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-fv">
    <?php foreach ($data['reports'] as $report): ?>
        <?php
        $mark = $report['reading'] === 'threat'
            ? 'mal'
            : ($report['reading'] === 'benign' ? 'ben' : 'unknown');
        ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <span class="vp-rw-verdict vp-rw-v-<?= h($mark) ?>"><?=
                    h($report['ratio']) ?></span>
                <span class="vp-rf-name font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $report['module'])
                    ) ?></span>
                <?php if ($report['verdict'] !== null): ?>
                    <span class="vp-rf-dim"><?=
                        h($report['verdict']) ?></span>
                <?php endif; ?>
                <?php if ($report['permalink'] !== null): ?>
                    <a class="vp-rf-link"
                       href="<?= h($report['permalink']) ?>"
                       rel="noreferrer noopener"
                       target="_blank"><?= h(__('report')) ?></a>
                <?php endif; ?>
            </div>
            <dl class="vp-rf-pairs">
                <?php if ($report['first_submission'] !== null): ?>
                    <dt><?= h(__('First submission')) ?></dt>
                    <dd><?= h(date('Y-m-d',
                        $report['first_submission'])) ?></dd>
                <?php endif; ?>
                <?php if ($report['last_submission'] !== null): ?>
                    <dt><?= h(__('Last submission')) ?></dt>
                    <dd><?= h(date('Y-m-d',
                        $report['last_submission'])) ?></dd>
                <?php endif; ?>
                <?php if ($report['severity'] !== null): ?>
                    <dt><?= h(__('Severity')) ?></dt>
                    <dd><?= h($report['severity']) ?></dd>
                <?php endif; ?>
                <?php if ($report['threat_score'] !== null): ?>
                    <dt><?= h(__('Threat score')) ?></dt>
                    <dd><?= h($report['threat_score']) ?></dd>
                <?php endif; ?>
                <?php if ($report['community_score'] !== null): ?>
                    <dt><?= h(__('Community score')) ?></dt>
                    <dd><?= h($report['community_score']) ?></dd>
                <?php endif; ?>
            </dl>
            <?php if ($report['comment'] !== null): ?>
                <p class="vp-rf-note"><?= h($report['comment']) ?></p>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
