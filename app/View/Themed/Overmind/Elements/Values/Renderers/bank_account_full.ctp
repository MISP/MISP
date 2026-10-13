<?php
/**
 * The account record, as the source stated it.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-bank">
    <?php foreach ($data['accounts'] as $account): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($account['iban'] !== null): ?>
                    <span class="vp-rf-key font-monospace"><?=
                        h($account['iban']) ?></span>
                <?php endif; ?>
                <?php if ($account['institution'] !== null): ?>
                    <span class="vp-rf-name"><?=
                        h($account['institution']) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $account['module'])
                    ) ?></span>
            </div>
            <dl class="vp-rf-pairs">
                <?php
                $fields = array(
                    __('BIC') => $account['bic'],
                    __('Country') => $account['country'],
                    __('Holder') => $account['holder'],
                    __('Currency') => $account['currency'],
                    __('Status') => $account['status'],
                );
                ?>
                <?php foreach ($fields as $label => $value): ?>
                    <?php if ($value !== null): ?>
                        <dt><?= h($label) ?></dt>
                        <dd><?= h($value) ?></dd>
                    <?php endif; ?>
                <?php endforeach; ?>
                <?php if ($account['balance'] !== null): ?>
                    <dt><?= h(__('Balance')) ?></dt>
                    <dd class="font-monospace"><?= h(number_format(
                        $account['balance'], 2)) ?></dd>
                <?php endif; ?>
            </dl>
        </div>
    <?php endforeach; ?>
</div>
