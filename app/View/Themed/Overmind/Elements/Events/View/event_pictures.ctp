<?php
$eventId = (int)($data['Event']['id'] ?? 0);
$fetchUrl = $baseurl . '/events/viewEventPictures/' . $eventId;
$distributions = [];
foreach ($this->DistributionLevel->all() as $level => $meta) {
    $distributions[$level] = ['label' => $meta['label'], 'icon' => $meta['icon']];
}
$strings = [
    'one' => __('1 picture'),
    'many' => __('%s pictures'),
    'carousel' => __('slideshow'),
    'carouselLabel' => __('Pictures of this event'),
    'slideLabel' => __('Picture %s of %s: %s'),
    'counter' => __('%s / %s'),
    'previous' => __('Previous picture'),
    'next' => __('Next picture'),
    'enlarge' => __('Enlarge'),
    'strip' => __('All pictures'),
    'inObject' => __('%s object'),
    'viewerLabel' => __('Pictures of this event'),
    'actualSize' => __('Actual size'),
    'actualSizeHint' => __('Show the picture at its actual size'),
    'fit' => __('Fit to screen'),
    'download' => __('Download'),
    'attribute' => __('Attribute'),
    'attributeHint' => __('Show the attribute this picture belongs to'),
    'close' => __('Close'),
    'keysBrowse' => __('to browse'),
    'keysClose' => __('to close'),
];
?>
<div class="card shadow-sm mb-3 ep-card" id="pictures-card" hidden>
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-2">
            <div class="misp-icon-tile rounded-2 d-flex align-items-center justify-content-center"
                 style="width:36px;height:36px;--tile:#0284c7;--tile-bg:#0284c740;">
                <i class="fas fa-images" style="font-size:1rem;"></i>
            </div>
            <div class="me-auto min-w-0">
                <div class="fw-bold lh-1"><?= __('Pictures') ?></div>
                <div class="small text-muted mt-1" data-ep-sub></div>
            </div>
            <button type="button"
                    class="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
                    data-ep-open
                    title="<?= __('Open in the viewer') ?>"
                    aria-label="<?= __('Open in the viewer') ?>">
                <i class="fas fa-expand"></i>
            </button>
        </div>
    </div>
    <div data-ep-body></div>
</div>

<script>
(function () {
    var card = document.getElementById('pictures-card');
    var fetchUrl = <?= json_encode($fetchUrl) ?>;
    var options = {
        strings: <?= json_encode($strings) ?>,
        distributions: <?= json_encode($distributions) ?>
    };

    function load() {
        fetch(fetchUrl, {
            cache: 'no-store',
            headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }
        })
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                return r.json();
            })
            .then(function (pictures) {
                EventPictures.mount(card, Array.isArray(pictures) ? pictures : [], options);
            })
            .catch(function () {
                card.hidden = true;
            });
    }

    // A picture attached from the attribute modal lands without a page load.
    document.addEventListener('misp:attributes-changed', load);
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', load);
    } else {
        load();
    }
}());
</script>
