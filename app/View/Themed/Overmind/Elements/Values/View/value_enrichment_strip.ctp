<?php
/**
 * The promoted widgets: one row, five at most, above the module rows.
 *
 * **The geometry is the decision.** This panel was measured at 179px
 * on a four-module value and ~180px was accepted as the budget for a
 * full-width panel of this kind. A row of five widgets at roughly
 * 190px sits inside that same order of magnitude; a stack of five
 * would be 500–1000px and would make enrichment the tallest thing on
 * the Overview, which is not what an overview is. So the row scrolls
 * sideways before it grows, and each widget clips at 150px.
 *
 * **One widget per shape**, whatever answered. Where three modules all
 * returned a geolocation the renderer merged them and this draws one
 * map; what the other two said is still on the rows below as chips.
 * Five *different* visual answers, never three maps.
 *
 * **A slot with no answer keeps its place in the row.** The order is
 * the profile's request, so a gap in it is information, and closing it
 * up would report four answers to a reader who asked for five and got
 * four. The slot says *not asked*.
 *
 * What it does **not** say is which module to press, and that is not
 * an omission: a slot is a shape, a run is a module, and a mapping
 * between the two is precisely the roster this design refuses to keep.
 * The Enrichment tab is where every module has its own control, so the
 * slot points there rather than guessing.
 *
 * **On a profile that marks nothing `auto`, this row is final on
 * load**, like everything else the Overview draws. Where some modules
 * are still answering it says so and how many, and redraws itself once
 * they have landed — because a widget that changed silently would be a
 * page arguing with what a reader had already read.
 *
 * **What it draws, the rows below do not repeat.** The modules whose
 * whole answer is in this row travel with it, because the browser
 * reads them off the redraw: a module that fired on arrival has a
 * chip row until its answer lands, and the strip that comes back is
 * what says the row has been taken over.
 *
 * @var array $strip From the panel's `strip`
 * @var string $valueB64
 * @var string $baseurl
 * @var int $pending Modules still answering
 * @var array $drawn Modules this row answers for
 */
$pending = isset($pending) ? (int)$pending : 0;
$drawn = isset($drawn) ? $drawn : array();
if (empty($strip['slots']) && $pending < 1) {
    return;
}

/**
 * A shape id as a heading.
 *
 * Derived rather than looked up, because a table of seventeen labels
 * is a second place for a shape's name to live and the id is already
 * written to be read: every one of them is words with hyphens between.
 *
 * @param string $shape
 * @return string
 */
$label = function ($shape) {
    return ucfirst(str_replace('-', ' ', $shape));
};

// A drawn cell with a full drawing is a tile: it opens that drawing under
// the row (js/tile-drawer.js).
$positions = array();
foreach ($strip['slots'] as $slot) {
    if ($slot['widget'] !== null && $slot['widget']['full'] !== null) {
        $positions[$slot['shape']] = count($positions);
    }
}
$tileCount = count($positions);
?>
<div class="vp-eb-strip" data-vp-eb-strip
     data-vp-eb-drawn="<?= h(implode(',', $drawn)) ?>">
    <?php foreach ($strip['slots'] as $slot): ?>
        <?php
        $widget = $slot['widget'];
        $at = $positions[$slot['shape']] ?? null;
        ?>
        <div class="vp-eb-cell<?= $widget === null
             ? ' vp-eb-cell-empty' : '' ?>"
             data-vp-eb-shape="<?= h($slot['shape']) ?>"
             <?php if ($at !== null): ?>
                 role="button" tabindex="0" aria-expanded="false"
                 aria-controls="vp-eb-drawer"
                 aria-label="<?= h(sprintf(__('%1$s, from %2$s'),
                    $label($slot['shape']),
                    implode(', ', $widget['modules']))) ?>"
                 data-td-tile
                 data-td-name="<?= h($label($slot['shape'])) ?>"
                 data-td-pos="<?= h(sprintf(__('%1$s of %2$s'), $at + 1,
                    $tileCount)) ?>"
             <?php endif; ?>>
            <div class="vp-eb-cell-head">
                <span class="vp-eb-cell-name"><?=
                    h($label($slot['shape'])) ?></span>
                <?php if ($widget !== null): ?>
                    <span class="vp-eb-cell-src font-monospace"
                          title="<?= h(implode(', ',
                            $widget['modules'])) ?>"><?=
                        h(implode(', ', $widget['modules'])) ?></span>
                <?php endif; ?>
            </div>
            <?php if ($widget === null): ?>
                <div class="vp-eb-cell-none">
                    <span class="vp-eb-cell-none-w"><?=
                        h(__('not asked')) ?></span>
                    <a class="vp-eb-cell-run"
                       href="<?= h($baseurl . '/values/view/'
                        . $valueB64 . '#tab-enrichment') ?>"><?=
                        h(__('Enrichment tab')) ?></a>
                </div>
            <?php else: ?>
                <?= $this->element($widget['compact'], array(
                    'data' => $widget['data'],
                )) ?>
                <?php if ($widget['ran_at'] !== null): ?>
                    <div class="vp-eb-cell-age"><?= $this->element(
                        'Values/View/value_enrichment_age',
                        array('askedAge' => max(0, time()
                            - (int)$widget['ran_at']))
                    ) ?></div>
                <?php endif; ?>
                <?php if ($at !== null): ?>
                    <?= $this->element(
                        'Values/View/value_enrichment_strip_panel',
                        array(
                            'widget' => $widget,
                            'name' => $label($slot['shape']),
                            'valueB64' => $valueB64,
                            'baseurl' => $baseurl,
                        )
                    ) ?>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    <?php endforeach; ?>

    <?php if ($pending > 0): ?>
        <?php
        /*
         * A cell rather than a line above the row, so the reader can
         * see that the row is not the whole of it without the row
         * jumping when the answers land: this is the space they will
         * arrive in.
         */
        ?>
        <div class="vp-eb-cell vp-eb-cell-wait" data-vp-eb-waiting>
            <div class="vp-eb-cell-head">
                <span class="vp-eb-cell-name"><?=
                    h(__('asking')) ?></span>
            </div>
            <div class="vp-eb-cell-none">
                <span class="vp-eb-cell-none-w">
                    <i class="fas fa-circle-notch fa-spin"
                       aria-hidden="true"></i>
                    <?= h(sprintf(
                        __n('%s module is still answering',
                            '%s modules are still answering', $pending),
                        $pending
                    )) ?>
                </span>
            </div>
        </div>
    <?php endif; ?>
</div>
