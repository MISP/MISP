<?php
/**
 * Every placing this value has, with the source of each.
 *
 * The compact form picks the newest answer and says so in one line;
 * this is where the disagreement lives. Three databases placing one
 * address in three cities is a finding about the databases, and the
 * only place it can be read is a table with a source column.
 *
 * **The map asks nobody for anything.** It is the same baked Natural
 * Earth outline the compact widget draws, at the size a pane affords —
 * so it is the rendering on every instance rather than the one an
 * administrator has opted in to, and the table below it carries the
 * sources either way. A tile fetch would say no more about *where*
 * than this does; what it would add is a network round trip per
 * reader and a dependency on a server outside the instance.
 *
 * @var array $data
 */
$points = $data['points'];
$places = $data['places'];
// On the event page: the objects' areas too, and no agreement to report.
$eventScope = !empty($this->viewVars['vpEventScope']);
$boxes = $eventScope ? array_values(array_filter(
    array_column($data['extents'] ?? array(), 'box')
)) : array();
?>
<div class="vp-rf vp-rf-geo">
    <?php if (!empty($points) || !empty($boxes)): ?>
        <?= $this->element('Values/Renderers/world_outline') ?>
        <svg class="vp-rf-plot" viewBox="0 6 360 142"
             preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <rect x="0" y="6" width="360" height="142"
                  class="vp-rw-plot-bg"/>
            <use href="#vp-world" x="0" y="0" width="360" height="180"/>
            <?= $this->element('Values/Renderers/geolocation_boxes',
                array('boxes' => $boxes, 'min' => 3)) ?>
            <?= $this->element('Values/Renderers/geolocation_points',
                array('points' => $points, 'halo' => 7, 'dot' => 3)) ?>
        </svg>
    <?php endif; ?>

    <?php if (!$eventScope && !$data['agreed']): ?>
        <p class="vp-rf-note"><?= h(sprintf(
            __('%1$s sources place this value in %2$s different'
                . ' locations.'),
            count($data['sources']),
            count($places)
        )) ?></p>
    <?php endif; ?>

    <?php if (!empty($points) || !empty($places)): ?>
    <table class="table table-sm vp-rf-table">
        <thead>
            <tr>
                <th scope="col"><?= h(__('Place')) ?></th>
                <th scope="col"><?= h(__('Country')) ?></th>
                <th scope="col"><?= h(__('Coordinates')) ?></th>
                <th scope="col"><?= h(__('Source')) ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            /*
             * The points where there are any and the named places
             * otherwise: a module that resolved a country and no
             * coordinates has still said something, and a table built
             * from the points alone would drop it.
             */
            $rows = empty($points) ? $places : $points;
            ?>
            <?php foreach ($rows as $row): ?>
                <tr>
                    <td><?= h($row['city'] === null
                        ? '—' : $row['city']) ?><?php
                        if (!empty($row['region'])): ?>
                        <span class="vp-rf-dim"><?=
                            h($row['region']) ?></span>
                    <?php endif; ?></td>
                    <td><?= h($row['country'] === null
                        ? '—' : $row['country']) ?><?php
                        if (!empty($row['code'])
                            && $row['code'] !== $row['country']): ?>
                        <span class="vp-rf-dim"><?=
                            h($row['code']) ?></span>
                    <?php endif; ?></td>
                    <td class="font-monospace"><?= isset($row['lat'])
                        ? h(sprintf('%.4f, %.4f', $row['lat'],
                            $row['lon']))
                        : '—' ?><?php if (!empty($row['radius'])): ?>
                        <span class="vp-rf-dim" title="<?= h(__(
                            'Accuracy radius: the place may be anywhere'
                                . ' this far from these coordinates.'
                        )) ?>">±<?= h(sprintf(
                            __('%s km'),
                            preg_replace('/\.0$/', '', number_format(
                                $row['radius'],
                                $row['radius'] < 10 ? 1 : 0
                            ))
                        )) ?></span>
                    <?php endif; ?></td>
                    <td class="font-monospace vp-rf-dim"><?=
                        $this->element('Values/Renderers/source_cell',
                            array('sources' => $row['module'])
                        ) ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</div>
