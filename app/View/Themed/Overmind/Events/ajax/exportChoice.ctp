<?php

$exports = $exports ?? [];
$uid = 'evt-export-' . dechex(mt_rand());
/* Past a handful the list would push the footer off screen. */
$scrolls = count($exports) > 6;
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'event',
        'eyebrow' => __('Event'),
        'title' => __('Download event'),
        'description' => __('Every format is a direct download of this event.'),
        'titleIcon' => 'fas fa-download',
        'icon' => 'fas fa-download',
    ]) ?>

    <div class="px-4 py-4">
        <?php if (empty($exports)): ?>
            <p class="mb-0 lh-base text-body-secondary">
                <?= __('No export format is available for this event.') ?>
            </p>
        <?php else: ?>
            <div class="border rounded-2 overflow-hidden">
                <div<?= $scrolls ? ' style="max-height:19rem; overflow-y:auto;"' : '' ?>>
                    <?php $first = true; foreach ($exports as $key => $export): ?>
                        <?php
                        $rowId = $uid . '-' . preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$key);
                        $hasOption = !empty($export['checkbox']) && !empty($export['checkbox_set']);
                        $optionOn = $hasOption && isset($export['checkbox_default']);
                        ?>
                        <div class="px-3 py-2<?= $first ? '' : ' border-top' ?>">
                            <a class="d-flex align-items-center justify-content-between gap-3 text-decoration-none"
                               id="<?= h($rowId) ?>-link"
                               href="<?= h($optionOn ? $export['checkbox_set'] : $export['url']) ?>"
                               data-url-off="<?= h($export['url']) ?>"
                               data-url-on="<?= h($hasOption ? $export['checkbox_set'] : $export['url']) ?>">
                                <span class="fw-semibold text-body" style="font-size:.85rem;">
                                    <?= h($export['text']) ?>
                                </span>
                                <i class="fas fa-download text-event flex-shrink-0" style="font-size:.8rem;"></i>
                            </a>

                            <?php if ($hasOption): ?>
                                <div class="form-check mt-1 mb-0">
                                    <input class="form-check-input" type="checkbox"
                                           id="<?= h($rowId) ?>-opt"
                                           data-target="<?= h($rowId) ?>-link"<?= $optionOn ? ' checked' : '' ?>>
                                    <label class="form-check-label text-body-secondary"
                                           for="<?= h($rowId) ?>-opt" style="font-size:.75rem;">
                                        <?= h($export['checkbox_text']) ?>
                                    </label>
                                </div>
                            <?php endif; ?>
                        </div>
                        <?php $first = false; ?>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'event',
        'bleed' => true,
        'meta' => [['label' => __('Event'), 'id' => $id]],
        'cancel' => ['label' => __('Close'), 'icon' => 'fas fa-xmark'],
        'submit' => false,
    ]) ?>
</div>

<script>
(function () {
    // A ticked option means a different URL for the same format.
    document.querySelectorAll('[id^="<?= $uid ?>-"][data-target]').forEach(function (box) {
        box.addEventListener('change', function () {
            var link = document.getElementById(box.dataset.target);
            if (link) {
                link.setAttribute('href', box.checked ? link.dataset.urlOn : link.dataset.urlOff);
            }
        });
    });
})();
</script>
