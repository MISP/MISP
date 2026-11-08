<?php
/**
 * The whole document as the content of #mainModal, which the rail's JSON
 * action renders from a template in the page (analystProfileRaw()).
 *
 * In the editor it is a textarea a paste replaces the profile through.
 * The modal sits outside `#ap-form`, so the textarea and its submit join
 * the form through their `form` attribute. Closing the modal disables the
 * textarea (analyst-profile.js): `edit` prefers a pasted document over
 * the sections, so a stale one would win the next save.
 *
 * @var array $profile
 * @var string $raw
 * @var bool $editable
 * @var array|null $parse A refused paste, with its line
 */
$size = sprintf('%.1f KB', strlen($raw) / 1024);
echo $this->element('genericElementsBS5/Forms/modal_header', array(
    'eyebrow' => __('Analyst Profiles'),
    'title' => __('Raw JSON'),
    'description' => $editable
        ? sprintf(__('The whole document · %s. Pasting one replaces it —'
            . ' nothing is merged.'), $size)
        : sprintf(__('The whole document · %s'), $size),
    'titleIcon' => 'fas fa-code',
    'icon' => 'fas fa-code',
    'accent' => 'primary',
));
?>
<div class="px-4 py-3">
    <?php if (!$editable): ?>
        <pre class="ap-raw"><?= h($raw) ?></pre>
    <?php else: ?>
        <?php if (!empty($parse)): ?>
            <div class="wb-note bad mb-2">
                <b><?= h(__('Not saved.')) ?></b>
                <?= h($parse['error']) ?>
                <?php if ($parse['line'] !== null): ?>
                    <?= h(sprintf(__('Line %s.'), $parse['line'])) ?>
                <?php endif; ?>
                <div class="wb-sub mt-1">
                    <?= h(__('The box below holds what you posted.')) ?>
                </div>
            </div>
        <?php endif; ?>
        <textarea class="form-control font-monospace" id="ap-raw" rows="24"
                  form="ap-form" spellcheck="false"
                  aria-label="<?= h(__('Raw JSON')) ?>"
                  name="data[AnalystProfile][parameters_json]"><?= h($raw) ?></textarea>
    <?php endif; ?>
</div>
<?= $this->element('genericElementsBS5/Forms/modal_footer', array(
    'accent' => 'primary',
    'bleed' => true,
    'align' => 'between',
    'hint' => $editable
        ? __('If the JSON will not parse, nothing is saved. Closing drops the'
            . ' paste.')
        : __('Read-only. Export it to keep a copy.'),
    'buttons' => array(array(
        'href' => $this->Html->url(array('action' => 'export', $profile['id'])),
        'icon' => 'fas fa-file-export',
        'label' => __('Export JSON'),
    )),
    'cancel' => array('label' => __('Close'), 'icon' => 'fas fa-xmark'),
    'submit' => $editable
        ? array(
            'label' => __('Replace the document'),
            'icon' => 'fas fa-file-import',
            'attrs' => array('form' => 'ap-form'),
        )
        : false,
)) ?>
