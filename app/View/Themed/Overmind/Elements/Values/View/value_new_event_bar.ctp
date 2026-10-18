<?php
/**
 * The bar the picked enrichment findings collect in, and the strings
 * value-new-event.js speaks with.
 *
 * @var string $value
 * @var string $valueB64
 */
$token = isset($this->request->params['_Token']['key'])
    ? $this->request->params['_Token']['key']
    : '';
?>
<div class="vp-ne-bar" data-vp-ne-bar role="region"
     aria-label="<?= h(__('Picked findings')) ?>"
     data-key="<?= h(hash('sha256', $value)) ?>"
     data-url="<?= h($baseurl . '/values/newEvent/' . $valueB64) ?>"
     data-token="<?= h($token) ?>"
     data-pick="<?= h(__('Pick')) ?>"
     data-picked="<?= h(__('Picked')) ?>"
     data-findings-one="<?= h(__('%s finding picked')) ?>"
     data-findings-many="<?= h(__('%s findings picked')) ?>"
     data-modules-one="<?= h(__('from %s module')) ?>"
     data-modules-many="<?= h(__('from %s modules')) ?>"
     data-created="<?= h(__('Event #%s created with the value.')) ?>"
     data-created-one="<?= h(__('Event #%s created with the value and 1 finding.')) ?>"
     data-created-many="<?= h(__('Event #%s created with the value and %s findings.')) ?>"
     data-failed="<?= h(__('%s findings could not be added; the event holds the rest.')) ?>"
     data-open="<?= h(__('Open event')) ?>"
     data-close="<?= h(__('Close')) ?>"
     data-error="<?= h(__('The event could not be created.')) ?>">
    <div class="vp-ne-bar-inner">
        <span class="vp-ne-bar-count">
            <i class="fas fa-layer-group" aria-hidden="true"></i>
            <span data-vp-ne-count></span>
        </span>
        <span class="vp-ne-bar-acts">
            <button type="button" class="btn btn-sm btn-outline-secondary" data-vp-ne-clear>
                <i class="fas fa-xmark" aria-hidden="true"></i>
                <?= h(__('Clear')) ?>
            </button>
            <button type="button" class="btn btn-sm btn-primary fw-semibold" data-vp-ne-open>
                <i class="fas fa-calendar-plus" aria-hidden="true"></i>
                <?= h(__('New event…')) ?>
            </button>
        </span>
    </div>
</div>
<div class="vp-ne-toasts" aria-live="polite" aria-atomic="true"></div>
