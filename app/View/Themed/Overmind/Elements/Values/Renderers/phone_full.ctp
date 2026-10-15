<?php
/**
 * The number decomposed, and the handset if one was described.
 *
 * Two templates answer different halves of this — how the number is
 * built, and what device carried it — so the record is one list rather
 * than two blocks. A reader asking *whose number is this* does not
 * care which template a field came from.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-phone">
    <?php foreach ($data['numbers'] as $number): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($number['number'] !== null): ?>
                    <span class="vp-rf-key font-monospace"><?=
                        h($number['number']) ?></span>
                <?php endif; ?>
                <?php if ($number['country'] !== null): ?>
                    <span class="vp-rf-name"><?=
                        h($number['country']) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $number['module'])
                    ) ?></span>
            </div>
            <dl class="vp-rf-pairs">
                <?php
                $fields = array(
                    __('Carrier') => $number['carrier'],
                    __('Line type') => $number['line_type'],
                    __('Destination code') => $number['destination'],
                    __('Subscriber') => $number['subscriber'],
                    __('Brand') => $number['brand'],
                    __('Model') => $number['model'],
                    __('IMEI') => $number['imei'],
                    __('IMSI') => $number['imsi'],
                    __('ICCID') => $number['iccid'],
                    __('Serial') => $number['serial'],
                );
                ?>
                <?php foreach ($fields as $label => $value): ?>
                    <?php if ($value !== null): ?>
                        <dt><?= h($label) ?></dt>
                        <dd><?= h($value) ?></dd>
                    <?php endif; ?>
                <?php endforeach; ?>
            </dl>
        </div>
    <?php endforeach; ?>
</div>
