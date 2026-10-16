<?php
/**
 * Every certificate, newest first, with what it was for.
 *
 * The subject alternative names are the column an analyst actually
 * pivots on — a certificate covering eleven unrelated domains on one
 * address is a shared host, and a certificate covering one is not —
 * so they are drawn in full rather than counted.
 *
 * @var array $data
 */
$now = time();
?>
<div class="vp-rf vp-rf-cert">
    <table class="table table-sm vp-rf-table">
        <thead>
            <tr>
                <th scope="col"><?= h(__('Subject')) ?></th>
                <th scope="col"><?= h(__('Issuer')) ?></th>
                <th scope="col"><?= h(__('Valid from')) ?></th>
                <th scope="col"><?= h(__('Valid to')) ?></th>
                <th scope="col"><?= h(__('Also covers')) ?></th>
                <th scope="col"><?= h(__('Source')) ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($data['certificates'] as $cert): ?>
                <?php
                $expired = $cert['not_after'] !== null
                    && $cert['not_after'] < $now;
                ?>
                <tr class="<?= $expired ? 'vp-rf-past' : '' ?>">
                    <td>
                        <?= h($cert['subject'] === null
                            ? '—' : $cert['subject']) ?>
                        <?php if ($cert['fingerprint'] !== null): ?>
                            <div class="vp-rf-dim font-monospace"><?=
                                h($cert['fingerprint']) ?></div>
                        <?php endif; ?>
                    </td>
                    <td><?= h($cert['issuer'] === null
                        ? '—' : $cert['issuer']) ?></td>
                    <td><?= h($cert['not_before'] === null
                        ? '—' : date('Y-m-d', $cert['not_before'])) ?></td>
                    <td><?= h($cert['not_after'] === null
                        ? '—' : date('Y-m-d', $cert['not_after'])) ?><?php
                        if ($expired): ?>
                        <span class="vp-rf-dim"><?=
                            h(__('expired')) ?></span>
                    <?php endif; ?></td>
                    <td><?= h(empty($cert['names'])
                        ? '—' : implode(', ', $cert['names'])) ?></td>
                    <td class="font-monospace vp-rf-dim"><?=
                        $this->element('Values/Renderers/source_cell',
                            array('sources' => $cert['sources'])
                        ) ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
