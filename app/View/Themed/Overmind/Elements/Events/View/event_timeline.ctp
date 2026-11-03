<?php
/**
 * The Timeline tab: filled by event-seen-timeline.js from
 * events/viewEventTimeline the first time the tab is shown.
 *
 * Laid out as the other tabs: the filter bar over the card, the search and the
 * Filters panel on its left, what the rows are placed by on its right. The
 * bar wears the index filter bars' classes (index-filters.css) but filters
 * here, so it has no data-ifp-bar; the script fills the panel and the basis
 * switch.
 */
$eventId = (int)($data['Event']['id'] ?? 0);
$suffix = $extensionSuffix ?? '';

echo $this->element('genericElements/assetLoader', ['css' => ['index-filters']]);
?>
<div class="etl-index" data-timeline-index>
    <div class="ifp-bar d-flex flex-wrap align-items-center etl-bar">
        <label class="ifp-query" data-etl-query>
            <i class="fas fa-search ifp-q-icon" aria-hidden="true"></i>
            <input type="search" autocomplete="off" spellcheck="false" data-timeline-search
                   placeholder="<?= h(__('Search values…')) ?>" aria-label="<?= h(__('Search the timeline')) ?>">
            <span class="ifp-q-end">
                <button type="button" class="ifp-q-clear" data-etl-search-clear
                        title="<?= h(__('Clear the search')) ?>" aria-label="<?= h(__('Clear the search')) ?>">
                    <i class="fas fa-times" aria-hidden="true"></i>
                </button>
            </span>
        </label>
        <button type="button" class="ifp-fbtn" data-etl-filters
                aria-expanded="false" aria-controls="etl-filters-panel"
                title="<?= h(__('Show or hide the filters')) ?>">
            <i class="fas fa-sliders" aria-hidden="true"></i>
            <span><?= h(__('Filters')) ?></span>
            <span class="badge rounded-pill bg-primary" data-etl-filters-count hidden></span>
            <i class="fas fa-chevron-down ifp-caret" aria-hidden="true"></i>
        </button>
        <div class="ifp-panel etl-panel" id="etl-filters-panel" role="region"
             aria-label="<?= h(__('Filters')) ?>" data-etl-panel hidden></div>
        <div class="ifp-end">
            <div class="ifp-segv etl-basis" role="group" aria-label="<?= h(__('Place rows by')) ?>"
                 data-etl-basis-group></div>
        </div>
    </div>

    <div class="ifp-row etl-row" data-etl-row hidden>
        <span class="ifp-count" data-etl-count></span>
        <div class="ifp-chips" data-etl-chips></div>
    </div>

    <div class="card shadow-sm mb-3 etl" data-timeline
         data-url="<?= h($baseurl . '/events/viewEventTimeline/' . $eventId . $suffix . '.json') ?>">
        <div class="p-5">
            <?= $this->element('genericElementsBS5/loader', ['label' => __('Loading the timeline…')]) ?>
        </div>
    </div>
</div>
