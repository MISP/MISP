<?php
/**
 * The whole document, as the Document tab.
 *
 * In the editor it is a textarea a paste replaces the profile through.
 * The textarea posts only while its tab is on screen (analyst-profile.js
 * enables it then): `edit` prefers a pasted document over the sections,
 * so a live one beside them would win every save.
 *
 * @var array $profile
 * @var string $raw
 * @var bool $editable
 * @var bool $open Whether the Document tab is the one on screen
 * @var array|null $parse A refused paste, with its line
 */
$size = sprintf('%.1f KB', strlen($raw) / 1024);
?>
<section class="card ap-vcard">
    <div class="ap-vcard-h">
        <span class="ap-vcard-ico" aria-hidden="true"><i class="fas fa-code"></i></span>
        <span class="ap-vcard-t">
            <span class="ap-vcard-title"><?= h(__('Raw JSON')) ?></span>
            <span class="ap-vcard-blurb"><?= h($editable
                ? sprintf(__('The whole document · %s. Pasting one replaces it'
                    . ' — nothing is merged.'), $size)
                : sprintf(__('The whole document · %s'), $size)) ?></span>
        </span>
        <a class="btn btn-sm btn-outline-primary" href="<?= h($this->Html->url(
            array('action' => 'export', $profile['id']))) ?>">
            <i class="fas fa-file-export me-1" aria-hidden="true"></i><?= h(
                __('Export JSON')) ?></a>
    </div>
    <?php if (!$editable): ?>
        <pre class="ap-raw"><?= h($raw) ?></pre>
    <?php else: ?>
        <div class="ap-vcard-b">
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
                      spellcheck="false" aria-label="<?= h(__('Raw JSON')) ?>"
                      name="data[AnalystProfile][parameters_json]"
                      <?= $open ? '' : 'disabled' ?>><?= h($raw) ?></textarea>
            <div class="d-flex flex-wrap align-items-center gap-2 mt-2">
                <button type="submit" class="btn btn-sm btn-primary">
                    <?= h(__('Replace the document')) ?>
                </button>
                <span class="wb-sub"><?= h(__('If the JSON will not parse,'
                    . ' nothing is saved.')) ?></span>
            </div>
        </div>
    <?php endif; ?>
</section>
