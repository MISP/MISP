<?php
/**
 * The wallet's totals and every transaction through it.
 *
 * The counterparty column is what makes this a pivot rather than a
 * statement: the address on the other side of a transaction is itself
 * a value this page can be opened for. A transaction often has several,
 * so the cell shows the first and counts the rest rather than widening
 * to fit a set whose size nothing bounds.
 *
 * Fiat values are shown where the source carried them and never
 * computed here — a converted amount needs a rate and a date, and a
 * template that guessed either would be inventing evidence.
 *
 * @var array $data
 */
$wallet = $data['wallet'];
?>
<div class="vp-rf vp-rf-crypto">
    <?php if ($wallet !== null): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($wallet['address'] !== null): ?>
                    <span class="vp-rf-key font-monospace"><?=
                        h($wallet['address']) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $wallet['module'])
                    ) ?></span>
            </div>
            <dl class="vp-rf-pairs">
                <?php
                $totals = array(
                    __('Balance') => $wallet['balance'],
                    __('Received') => $wallet['received'],
                    __('Sent') => $wallet['sent'],
                    __('Transactions') => $wallet['transactions'],
                );
                ?>
                <?php foreach ($totals as $label => $value): ?>
                    <?php if ($value !== null): ?>
                        <dt><?= h($label) ?></dt>
                        <dd class="font-monospace"><?= h(rtrim(rtrim(
                            number_format($value, 8), '0'), '.')) ?><?php
                            if ($wallet['symbol'] !== null): ?>
                            <span class="vp-rf-dim"><?=
                                h($wallet['symbol']) ?></span>
                        <?php endif; ?></dd>
                    <?php endif; ?>
                <?php endforeach; ?>
            </dl>
        </div>
    <?php endif; ?>

    <?php if (!empty($data['transactions'])): ?>
        <table class="table table-sm vp-rf-table">
            <thead>
                <tr>
                    <th scope="col"><?= h(__('When')) ?></th>
                    <th scope="col"><?= h(__('Counterparty')) ?></th>
                    <th scope="col" class="text-end"><?=
                        h(__('Value')) ?></th>
                    <th scope="col" class="text-end"><?=
                        h(__('EUR')) ?></th>
                    <th scope="col" class="text-end"><?=
                        h(__('USD')) ?></th>
                    <th scope="col"><?= h(__('Transaction')) ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($data['transactions'] as $tx): ?>
                    <tr>
                        <td><?= h($tx['at'] === null
                            ? '—' : date('Y-m-d H:i', $tx['at'])) ?></td>
                        <td class="font-monospace"><?=
                            h($tx['counterparty'] === null
                                ? '—' : $tx['counterparty']) ?><?php
                            $more = count($tx['counterparties']) - 1;
                            if ($more > 0): ?><span
                                class="vp-rf-dim"><?= h(sprintf(
                                    ' +%d', $more
                                )) ?></span><?php endif; ?></td>
                        <td class="text-end font-monospace"><?=
                            h($tx['value'] === null ? '—'
                                : rtrim(rtrim(number_format(
                                    $tx['value'], 8), '0'), '.')) ?></td>
                        <td class="text-end"><?= h($tx['value_eur'] === null
                            ? '—' : number_format($tx['value_eur'],
                                2)) ?></td>
                        <td class="text-end"><?= h($tx['value_usd'] === null
                            ? '—' : number_format($tx['value_usd'],
                                2)) ?></td>
                        <td class="font-monospace vp-rf-dim"><?=
                            h($tx['number'] === null
                                ? '—' : $tx['number']) ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>
