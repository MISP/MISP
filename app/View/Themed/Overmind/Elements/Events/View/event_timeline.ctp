<?php
$eventId = (int)($data['Event']['id'] ?? 0);
$uid = 'event-timeline-' . $eventId;
$mayModify = !empty($isSiteAdmin) || $this->Acl->canModifyEvent($data);
// getEventTimeline reads `extended` only, not `extending`.
$suffix = strpos($extensionSuffix ?? '', '/extended:1') !== false ? '/extended:1' : '';

$strings = [
    'seenSummary' => __('%s attributes · %s objects · %s without first seen'),
    'sightingSummary' => __('%s sighting periods on %s attributes'),
    'empty' => __('Nothing to place on the timeline'),
    'noSightings' => __('No sighting on this event'),
    'positive' => __('Sighted'),
    'falsePositive' => __('False positive'),
    'overwrite' => __('Placed by the object\'s first-seen / last-seen attributes'),
    'tooMany' => __('%s items are too many to draw: showing how they spread over time instead.'),
    'many' => __('%s items to draw, the timeline may become slow.'),
    'drawAnyway' => __('Draw them anyway'),
    'failed' => __('Could not load the timeline:'),
    'chartTimestamp' => __('Timestamp'),
    'chartFirst' => __('First seen'),
    'chartLast' => __('Last seen'),
    'chartSightings' => __('Sightings'),
    'edit' => __('Edit'),
    'expand' => __('Give it a last seen'),
    'collapse' => __('Remove last seen'),
    'firstSeen' => __('First seen'),
    'lastSeen' => __('Last seen'),
    'atTimestamp' => __('No first seen: placed at its timestamp'),
    'noForm' => __('The edit form could not be read.'),
    'saved' => __('First / last seen saved'),
    'saveFailed' => __('Could not save:'),
    'clearTitle' => __('Clear first and last seen?'),
    'clearBody' => __('"%s" will go back to its timestamp on the timeline.'),
    'clearConfirm' => __('Clear'),
];

echo $this->element('genericElements/assetLoader', ['js' => ['overmind-event-timeline']]);
?>

<div class="card shadow-sm mb-3 ov-timeline" id="<?= $uid ?>"
     data-event-timeline
     data-event-id="<?= $eventId ?>"
     data-suffix="<?= h($suffix) ?>"
     data-may-modify="<?= $mayModify ? '1' : '0' ?>">
    <script type="application/json" data-timeline-strings><?= json_encode($strings, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>

    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2 flex-wrap">
            <div class="rounded-2 d-flex align-items-center justify-content-center flex-shrink-0 bg-event bg-opacity-10"
                 style="width:36px;height:36px;">
                <i class="fas fa-timeline text-event"></i>
            </div>
            <div class="me-auto">
                <div class="fw-bold lh-1"><?= __('Timeline') ?></div>
                <div class="small text-muted mt-1" data-timeline-summary>…</div>
            </div>

            <div class="btn-group btn-group-sm" role="group" aria-label="<?= __('Time scope') ?>">
                <input type="radio" class="btn-check" name="<?= $uid ?>-scope" id="<?= $uid ?>-seen"
                       value="seen" data-timeline-scope checked autocomplete="off">
                <label class="btn btn-outline-secondary" for="<?= $uid ?>-seen">
                    <i class="fas fa-arrows-left-right-to-line me-1"></i><?= __('First / last seen') ?>
                </label>
                <input type="radio" class="btn-check" name="<?= $uid ?>-scope" id="<?= $uid ?>-sightings"
                       value="sightings" data-timeline-scope autocomplete="off">
                <label class="btn btn-outline-secondary" for="<?= $uid ?>-sightings">
                    <i class="fas fa-eye me-1"></i><?= __('Sightings') ?>
                </label>
            </div>

            <div class="d-none" style="width:16rem;" data-timeline-search-box>
                <select class="form-select form-select-sm" data-timeline-search
                        data-placeholder="<?= __('Find an item…') ?>"
                        aria-label="<?= __('Find an item on the timeline') ?>"></select>
            </div>

            <div class="dropdown">
                <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle"
                        data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">
                    <i class="fas fa-sliders me-1"></i><?= __('Display') ?>
                </button>
                <div class="dropdown-menu dropdown-menu-end p-3 small" style="min-width:18rem;">
                    <label class="form-label d-flex mb-1" for="<?= $uid ?>-chars">
                        <?= __('Characters to show') ?>
                        <output class="ms-auto fw-semibold" data-timeline-chars-value>64</output>
                    </label>
                    <input type="range" class="form-range" id="<?= $uid ?>-chars"
                           min="8" max="2048" step="8" value="64" data-timeline-chars>
                    <div class="form-check form-switch mt-2">
                        <input class="form-check-input" type="checkbox" role="switch"
                               id="<?= $uid ?>-hide" data-timeline-hide-unseen>
                        <label class="form-check-label" for="<?= $uid ?>-hide">
                            <?= __('Hide items without first seen') ?>
                        </label>
                    </div>
                    <div class="form-check form-switch mt-2">
                        <input class="form-check-input" type="checkbox" role="switch"
                               id="<?= $uid ?>-local" data-timeline-local-time checked>
                        <label class="form-check-label" for="<?= $uid ?>-local">
                            <?= __('My timezone') ?> (UTC<span data-timeline-tz></span>)
                            <span class="d-block text-body-secondary"><?= __('Off: dates in UTC') ?></span>
                        </label>
                    </div>
                    <button type="button" class="btn btn-sm btn-outline-secondary w-100 mt-3" data-timeline-fit>
                        <i class="fas fa-maximize me-1"></i><?= __('Fit all items') ?>
                    </button>
                </div>
            </div>

            <button type="button" class="btn btn-sm btn-outline-secondary" data-timeline-fullscreen
                    title="<?= __('Toggle fullscreen') ?>">
                <i class="fas fa-expand"></i>
            </button>
        </div>
    </div>

    <div data-timeline-message></div>

    <div class="position-relative">
        <div data-timeline-canvas></div>
        <div class="d-none p-3" style="height:440px;" data-timeline-chart><canvas></canvas></div>
        <div class="position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center bg-body bg-opacity-75 d-none"
             style="z-index:5;min-height:120px;" data-timeline-loading>
            <div class="spinner-border spinner-border-sm text-secondary me-2" role="status"></div>
            <span class="small text-body-secondary"><?= __('Loading') ?></span>
        </div>
    </div>

    <div class="d-none" data-timeline-selection></div>

    <div class="d-flex align-items-center flex-wrap gap-3 px-3 py-2 border-top small text-body-secondary">
        <span class="d-flex align-items-center gap-3" data-timeline-legend-seen>
            <span class="d-flex align-items-center gap-1">
                <span class="ov-tl-swatch attribute"></span><?= __('Attribute') ?>
            </span>
            <span class="d-flex align-items-center gap-1">
                <span class="ov-tl-swatch object"></span><?= __('Object') ?>
            </span>
            <span class="d-flex align-items-center gap-1">
                <span class="ov-tl-swatch attribute ov-no-seen"></span><?= __('No first seen: at its timestamp') ?>
            </span>
        </span>
        <span class="d-flex align-items-center gap-3 d-none" data-timeline-legend-sightings>
            <span class="d-flex align-items-center gap-1">
                <span class="ov-tl-swatch sighting_positive"></span><?= __('Sighted') ?>
            </span>
            <span class="d-flex align-items-center gap-1">
                <span class="ov-tl-swatch sighting_negative"></span><?= __('False positive') ?>
            </span>
        </span>
        <span class="ms-auto">
            <kbd>Alt</kbd> + <?= __('wheel to zoom') ?>
            <span data-timeline-hints-seen>
                · <kbd>Ctrl</kbd> + <?= __('click to select several') ?>
                · <?= __('double-click to edit') ?>
                <?php if ($mayModify): ?>
                · <?= __('drag to set first / last seen') ?>
                <?php endif; ?>
            </span>
        </span>
    </div>
</div>
