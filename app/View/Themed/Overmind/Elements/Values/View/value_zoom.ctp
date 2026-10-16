<?php
/**
 * The zoom control over a brushable activity chart.
 *
 * Four buttons and a caption, shared by the three callers phase 20
 * gave one brush. Buttons rather than a gesture, because phase 19
 * already spent the drag on selecting a period and §13.3 refuses to
 * conflate the two: a reader who wants to look closer at March must
 * not be made to filter the tab to March to do it. The wheel was
 * rejected for trapping the page under the reader's pointer, and the
 * double-click for colliding with the click that clears the brush.
 *
 * Rendered hidden, for the reason the brush is (§11.2): without the
 * script these buttons frame a chart they cannot move.
 *
 * `reset` is not a fifth step so much as the way back — it is the one
 * button whose target does not depend on where the reader is.
 *
 * @var array $grain Per-unit wording for what a bar is worth
 * @var string $zoomLabel Names the group for a screen reader
 * @var string $zoomAway What to say when the selection is off screen
 * @var string $zoomSelection Names the look-inside-the-selection step,
 *     and its presence is what offers that step at all
 * @var string $zoomNote Optional sentence under the buttons
 */
$grain = isset($grain) ? $grain : array();
$zoomAway = isset($zoomAway) ? $zoomAway : null;
$zoomNote = isset($zoomNote) ? $zoomNote : null;
$steps = array(
    array(
        'step' => 'out',
        'icon' => 'fas fa-magnifying-glass-minus',
        'title' => __('Show a wider span'),
    ),
    array(
        'step' => 'in',
        'icon' => 'fas fa-magnifying-glass-plus',
        'title' => __('Look inside the span on screen'),
    ),
    array(
        'step' => 'left',
        'icon' => 'fas fa-chevron-left',
        'title' => __('Move back — hold to keep moving'),
    ),
    array(
        'step' => 'right',
        'icon' => 'fas fa-chevron-right',
        'title' => __('Move forward — hold to keep moving'),
    ),
    array(
        'step' => 'reset',
        'icon' => 'fas fa-arrows-left-right-to-line',
        'title' => __('Show the whole span'),
    ),
);
/*
 * Offered only where the caller gave the zoom a selection to read.
 * It is a shortcut and never the only way in: §13.3's objection to
 * zoom-by-selection was that a reader who wants a closer look would be
 * made to filter to get one, and the four buttons above are why that
 * does not happen here.
 */
if (!empty($zoomSelection)) {
    $steps[] = array(
        'step' => 'selection',
        'icon' => 'fas fa-arrows-to-dot',
        'title' => $zoomSelection,
    );
}
?>
<div class="vp-zoom" data-vp-zoom hidden role="group"
     aria-label="<?= h($zoomLabel) ?>">
    <div class="vp-zoom-where">
        <?php
        /*
         * The span is labelled because it is not the only span a caller
         * may be stating. The Sightings navigator's own caption names
         * the range the table follows, one line above this one, and
         * two unlabelled date pairs on adjacent lines read as two
         * facts in two notations rather than as what they are: what
         * the chart shows, and what the list is filtered to.
         */
        ?>
        <span class="vp-zoom-lead"><?= h(__('showing')) ?></span>
        <span class="vp-zoom-range" data-vp-zoom-range></span>
        <span class="vp-zoom-grain" data-vp-zoom-grain></span>
        <?php
        /*
         * Whether what the reader has selected is still on screen. It
         * has to be said in words: the brush paints a selection that
         * has gone out of view as a fully dimmed strip, which is the
         * truthful painting and is also indistinguishable from an
         * undimmed one, because a uniform dim has nothing to contrast
         * against.
         */
        ?>
        <span class="vp-zoom-note" data-vp-zoom-note hidden></span>
    </div>
    <div class="vp-zoom-steps">
        <?php foreach ($steps as $step): ?>
            <button type="button" class="vp-zoom-step"
                    data-vp-zoom-step="<?= h($step['step']) ?>"
                    title="<?= h($step['title']) ?>"
                    aria-label="<?= h($step['title']) ?>">
                <i class="<?= h($step['icon']) ?>" aria-hidden="true"></i>
            </button>
        <?php endforeach; ?>
    </div>
    <?php
    /*
     * The per-unit wording is data rather than markup because §12.2's
     * argument survives the zoom: a bar means a different thing on each
     * caller, so only the caller can say what one is worth.
     */
    ?>
    <script type="application/json" data-vp-zoom-labels><?= json_encode(
        array('grain' => $grain, 'away' => $zoomAway)
    ) ?></script>
</div>
<?php if ($zoomNote !== null): ?>
    <div class="vp-facet-note"><?= h($zoomNote) ?></div>
<?php endif; ?>
