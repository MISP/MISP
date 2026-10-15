<?php
/**
 * Every service, with whatever banner the scan carried.
 *
 * The banner is the column this table exists for. A port number says
 * what protocol is probably there; a banner says what software, which
 * version, and therefore whether the vulnerability widget two slots
 * along is about this host.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-ports">
    <table class="table table-sm vp-rf-table">
        <thead>
            <tr>
                <th scope="col"><?= h(__('Port')) ?></th>
                <th scope="col"><?= h(__('Protocol')) ?></th>
                <th scope="col"><?= h(__('Service')) ?></th>
                <th scope="col"><?= h(__('Banner')) ?></th>
                <th scope="col"><?= h(__('First')) ?></th>
                <th scope="col"><?= h(__('Last')) ?></th>
                <th scope="col"><?= h(__('Source')) ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($data['services'] as $service): ?>
                <tr class="<?= $service['service'] !== null
                    ? 'vp-rf-hot' : '' ?>">
                    <td class="font-monospace"><?=
                        h($service['port']) ?></td>
                    <td><?= h($service['protocol']) ?></td>
                    <td><?= h($service['service'] === null
                        ? '—' : $service['service']) ?></td>
                    <td class="font-monospace"><?=
                        h($service['banner'] === null
                            ? '—' : $service['banner']) ?></td>
                    <td><?= h($service['first'] === null
                        ? '—' : date('Y-m-d', $service['first'])) ?></td>
                    <td><?= h($service['last'] === null
                        ? '—' : date('Y-m-d', $service['last'])) ?></td>
                    <td class="font-monospace vp-rf-dim"><?=
                        $this->element('Values/Renderers/source_cell',
                            array('sources' => $service['sources'])
                        ) ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
