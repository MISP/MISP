<?php
/**
 * The galaxy page's Matrix tab: the full matrix the event page opens in its
 * modal, the techniques events carry standing out.
 *
 * $matrix as GalaxiesController::viewMatrix() builds it.
 */
$texts = [
    'onEvent' => __('On an event'),
    'eventOne' => __('On 1 event'),
    'eventMany' => __('On %s events'),
    'subOf' => __('Sub-technique of %s'),
    'throughOne' => __('Through 1 sub-technique'),
    'throughMany' => __('Through %s sub-techniques'),
    'open' => __('Open the technique'),
    'openSub' => __('Open %s'),
    'close' => __('Close'),
    'failed' => __('Could not load the matrix.'),
];
$switchId = 'mx-hide-unused-' . (int)$matrix['galaxy']['id'];
?>
<div class="card shadow-sm mb-3 mx-inline" data-mx-inline
     data-url="<?= h($baseurl . '/galaxies/viewMatrix/' . (int)$matrix['galaxy']['id']) ?>"
     data-mx-text="<?= h(json_encode($texts)) ?>">
    <div class="mx-inline-head">
        <div class="mx-modal-legend">
            <span><span class="mx-sw"></span><?= __('Carried by events') ?></span>
        </div>
        <div class="form-check form-switch mx-modal-unused">
            <input class="form-check-input" type="checkbox" role="switch" id="<?= h($switchId) ?>" data-mx-hide-unused>
            <label class="form-check-label" for="<?= h($switchId) ?>"><?= __('Hide unused columns') ?></label>
        </div>
    </div>
    <div data-mx-inline-body>
        <?= $this->element('GalaxyMatrix/full', [
            'matrix' => $matrix,
            'lightIcon' => 'misp-icon misp-icon-attribute misp-simple',
        ]) ?>
    </div>
</div>
