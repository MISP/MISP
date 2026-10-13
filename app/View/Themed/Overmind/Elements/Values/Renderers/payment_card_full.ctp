<?php
/**
 * The card record.
 *
 * The number itself is never drawn and never will be: the shape this
 * widget is about is the *issuer* behind a prefix, and a page that
 * printed a full card number would be the one screen in MISP that
 * turns an indicator into a usable credential.
 *
 * @var array $data
 */
?>
<div class="vp-rf vp-rf-card">
    <?php foreach ($data['cards'] as $card): ?>
        <div class="vp-rf-block">
            <div class="vp-rf-head">
                <?php if ($card['scheme'] !== null): ?>
                    <span class="vp-rf-key"><?=
                        h($card['scheme']) ?></span>
                <?php endif; ?>
                <?php if ($card['iin'] !== null): ?>
                    <span class="vp-rf-name font-monospace"><?=
                        h($card['iin']) ?></span>
                <?php endif; ?>
                <span class="vp-rf-dim font-monospace"><?=
                    $this->element('Values/Renderers/source_cell',
                        array('sources' => $card['module'])
                    ) ?></span>
            </div>
            <dl class="vp-rf-pairs">
                <?php
                $fields = array(
                    __('Issuer') => $card['issuer'],
                    __('Holder') => $card['holder'],
                    __('Issued') => $card['issued'],
                    __('Expires') => $card['expires'],
                );
                ?>
                <?php foreach ($fields as $label => $value): ?>
                    <?php if ($value !== null): ?>
                        <dt><?= h($label) ?></dt>
                        <dd><?= h($value) ?></dd>
                    <?php endif; ?>
                <?php endforeach; ?>
            </dl>
            <?php if ($card['comment'] !== null): ?>
                <p class="vp-rf-note"><?= h($card['comment']) ?></p>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>
</div>
