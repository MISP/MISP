<?php
/**
 * The ranking over time, and any announcement that did not belong.
 *
 * A single position is a snapshot; the series is what says whether a
 * neighbourhood is getting worse. Where the source returned one date
 * only, the table has one row and says so by being one row rather than
 * by drawing a chart of a single point.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-prefix">
    <?php if (!empty($data['hijacks'])): ?>
        <?php foreach ($data['hijacks'] as $hijack): ?>
            <div class="vp-rf-block">
                <div class="vp-rf-head">
                    <span class="vp-rw-verdict vp-rw-v-mal"><?=
                        h(__('hijack')) ?></span>
                    <?php if ($hijack['prefix'] !== null): ?>
                        <span class="vp-rf-key font-monospace"><?=
                            h($hijack['prefix']) ?></span>
                    <?php endif; ?>
                    <span class="vp-rf-dim font-monospace"><?=
                        $this->element('Values/Renderers/source_cell',
                            array('sources' => $hijack['module'])
                        ) ?></span>
                </div>
                <dl class="vp-rf-pairs">
                    <?php if ($hijack['expected_asn'] !== null): ?>
                        <dt><?= h(__('Expected')) ?></dt>
                        <dd class="font-monospace"><?=
                            h($hijack['expected_asn']) ?></dd>
                    <?php endif; ?>
                    <?php if ($hijack['detected_asn'] !== null): ?>
                        <dt><?= h(__('Announced by')) ?></dt>
                        <dd class="font-monospace"><?=
                            h($hijack['detected_asn']) ?></dd>
                    <?php endif; ?>
                    <?php if ($hijack['start'] !== null): ?>
                        <dt><?= h(__('From')) ?></dt>
                        <dd><?= h(date('Y-m-d',
                            $hijack['start'])) ?></dd>
                    <?php endif; ?>
                    <?php if ($hijack['end'] !== null): ?>
                        <dt><?= h(__('Until')) ?></dt>
                        <dd><?= h(date('Y-m-d', $hijack['end'])) ?></dd>
                    <?php endif; ?>
                </dl>
                <?php if ($hijack['description'] !== null): ?>
                    <p class="vp-rf-prose"><?=
                        h($hijack['description']) ?></p>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <?php if (!empty($data['ranks'])): ?>
        <table class="table table-sm vp-rf-table">
            <thead>
                <tr>
                    <th scope="col"><?= h(__('Date')) ?></th>
                    <th scope="col" class="text-end"><?=
                        h(__('Position')) ?></th>
                    <th scope="col" class="text-end"><?=
                        h(__('Ranking')) ?></th>
                    <th scope="col"><?= h(__('Family')) ?></th>
                    <th scope="col"><?= h(__('Source')) ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($data['ranks'] as $rank): ?>
                    <tr>
                        <td><?= h($rank['at'] === null
                            ? '—' : date('Y-m-d', $rank['at'])) ?></td>
                        <td class="text-end font-monospace"><?=
                            h($rank['position'] === null ? '—'
                                : number_format($rank['position'])) ?></td>
                        <td class="text-end font-monospace"><?=
                            h($rank['ranking'] === null
                                ? '—' : $rank['ranking']) ?></td>
                        <td><?= h($rank['family'] === null
                            ? '—' : $rank['family']) ?></td>
                        <td class="font-monospace vp-rf-dim"><?=
                            $this->element('Values/Renderers/source_cell',
                                array('sources' => $rank['module'])
                            ) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
