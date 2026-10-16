<?php
/**
 * The full matrix modal, filled by misp-matrix.js one galaxy tab at a time.
 *
 * @var string $strongLabel legend of the strong state
 * @var string $lightLabel legend of the weaker state
 */
?>
<div class="modal fade mx-modal mx-hide-unused" id="mx-modal" tabindex="-1" aria-labelledby="mx-modal-title" aria-hidden="true">
    <div class="modal-dialog modal-fullscreen">
        <div class="modal-content">
            <div class="modal-header">
                <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center"
                     style="width:32px;height:32px;--tile:var(--bs-galaxy);--tile-bg:color-mix(in srgb, var(--bs-galaxy) 18%, transparent);">
                    <i class="fas fa-map" data-mx-modal-icon></i>
                </div>
                <h5 class="modal-title" id="mx-modal-title" data-mx-modal-title><?= __('Galaxy matrix') ?></h5>
                <div class="mx-modal-galaxies" role="group" aria-label="<?= h(__('Galaxy')) ?>" data-mx-modal-galaxies hidden></div>
                <div class="mx-modal-legend">
                    <span><span class="mx-sw"></span><?= h($strongLabel) ?></span>
                    <span><span class="mx-sw is-ind"></span><?= h($lightLabel) ?></span>
                </div>
                <div class="form-check form-switch mx-modal-unused">
                    <input class="form-check-input" type="checkbox" role="switch" id="mx-hide-unused" data-mx-hide-unused checked>
                    <label class="form-check-label" for="mx-hide-unused"><?= __('Hide unused columns') ?></label>
                </div>
                <button type="button" class="btn-close ms-2" data-bs-dismiss="modal" aria-label="<?= h(__('Close')) ?>"></button>
            </div>
            <div class="modal-body" data-mx-modal-body></div>
        </div>
    </div>
</div>
