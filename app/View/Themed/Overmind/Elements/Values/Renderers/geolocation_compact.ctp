<?php
/**
 * Where an address is, in 190×150.
 *
 * **The thumbnail is a position plot and not a tile fetch**, and that
 * is the geometry deciding rather than a preference. The strip is one
 * row of five widgets inside 200px; five tile-fetching maps in it
 * would be five map instances, five sets of network requests and five
 * scripts, on a panel whose whole argument is that it paints at the
 * speed of a database read. The real map is the full rendering on the
 * Enrichment pane, where there is one of it and room for it.
 *
 * So this draws a world outline and the points on it, from geometry
 * that ships as markup. It is a map in the sense that it says *where*,
 * and it says so with no request at all — which is also why it does
 * not change when the instance has tiles turned off.
 *
 * Pure: everything drawn comes from `prepare()`.
 *
 * @var array $data
 */
$place = $data['place'];
$points = $data['points'];
$city = $place === null ? null : $place['city'];
$country = $place === null ? null : $place['country'];
$code = $place === null ? null : $place['code'];

/*
 * The headline is the most specific thing known, because a reader who
 * already knows the country learns nothing from it — and a country is
 * the fallback rather than the answer.
 */
$headline = $city !== null ? $city : ($country !== null ? $country : null);
$sub = $city !== null && $country !== null ? $country : null;
$tagTitle = trim(($city === null ? '' : $city . ', ')
    . ($country === null ? '' : $country));

/*
 * On the event page the drawing is every place the objects name, not one
 * address's placing: several places are counted rather than named after
 * the newest, and areas and tracks are drawn and counted beside them.
 */
$eventScope = !empty($this->viewVars['vpEventScope']);
$extents = $eventScope ? ($data['extents'] ?? array()) : array();
$boxes = array_values(array_filter(array_column($extents, 'box')));
$extentNote = null;
if ($eventScope) {
    $placeCount = count($data['places']);
    if ($placeCount > 1) {
        $headline = sprintf(__n('%s place', '%s places', $placeCount),
            $placeCount);
        $countries = count(array_unique(array_filter(
            array_column($data['places'], 'country')
        )));
        $sub = $countries > 0 ? sprintf(
            __n('%s country', '%s countries', $countries),
            $countries
        ) : null;
        $code = null;
        $tagTitle = $headline . ($sub !== null ? ', ' . $sub : '');
    }
    $areas = count(array_filter($extents, function ($extent) {
        return $extent['template'] === 'geojson';
    }));
    $tracks = count($extents) - $areas;
    $extentNote = implode(' · ', array_filter(array(
        $areas ? sprintf(__n('%s area', '%s areas', $areas), $areas) : null,
        $tracks ? sprintf(__n('%s track', '%s tracks', $tracks), $tracks)
            : null,
    )));
    if ($headline === null && $extentNote !== '') {
        $headline = $extentNote;
        $extentNote = null;
    }
}
?>
<div class="vp-rw-in vp-rw-geo">
    <?php if (empty($points) && empty($boxes)): ?>
        <?php
        /*
         * A module that resolved a country and no coordinates. There
         * is nothing to draw and the place name is the whole answer,
         * so it is a line of text rather than a caption with no map
         * over it.
         */
        ?>
        <?php if ($headline !== null): ?>
            <div class="vp-rw-head" title="<?= h($tagTitle) ?>"><?=
                h($headline) ?></div>
            <?php if ($sub !== null): ?>
                <div class="vp-rw-sub"><?= h($sub) ?><?php
                    if ($code !== null && $code !== $sub): ?>
                    <span class="vp-rw-code"><?= h($code) ?></span>
                <?php endif; ?></div>
            <?php endif; ?>
        <?php else: ?>
            <div class="vp-rw-head vp-rw-quiet"><?=
                h(__('located')) ?></div>
        <?php endif; ?>
    <?php else: ?>
        <?php
        /*
         * Equirectangular, which is the projection a rectangle already
         * is: x is longitude and y is latitude, both linear. The
         * outline it is true against is the same Natural Earth
         * geometry the dashboard's map widgets draw, baked to a path
         * so that a coastline costs markup rather than a map library
         * and a 437 KB fetch — see `world_outline.ctp`.
         *
         * **The window is cropped to the points, and that is what buys
         * the room.** A whole world is 2.5 times as wide as it is
         * tall, so a cell 200px across can only ever give it 80px of
         * height — which is the shape a reader called squished, and
         * they were right: the continents were a third of the size the
         * cell could have drawn them at. Showing 260 degrees of
         * longitude instead of 360, centred on the points, is the same
         * map an eighth again as large in a box half again as tall,
         * and what falls off the edges is ocean either side of the
         * answer.
         *
         * The window follows the points in both axes, and latitude is
         * not the free choice longitude is: the caption sits over the
         * bottom of the panel, so a point the window leaves low is a
         * point under the words. Biasing it above centre is what keeps
         * a southern placing out from under its own name.
         *
         * Fitting a window to the points is drawing rather than
         * deciding — `prepare()` still owns every fact here, and the
         * pane rendering draws the same points against the whole
         * world, because there it fits.
         */
        $VIEW_W = 260;
        $VIEW_H = 142;
        $xs = array();
        $ys = array();
        foreach ($points as $point) {
            // A ring wider than the halo is kept whole in the window.
            $reach = $point['reach'] ?? null;
            $rx = $reach !== null && $reach[1] > 8 ? $reach[0] : 0;
            $ry = $reach !== null && $reach[1] > 8 ? $reach[1] : 0;
            array_push($xs, $point['lon'] + 180 - $rx,
                $point['lon'] + 180 + $rx);
            array_push($ys, 90 - $point['lat'] - $ry,
                90 - $point['lat'] + $ry);
        }
        foreach ($boxes as $box) {
            array_push($xs, $box[1] + 180, $box[3] + 180);
            array_push($ys, 90 - $box[2], 90 - $box[0]);
        }
        if ((max($xs) - min($xs)) > $VIEW_W - 30) {
            /*
             * Two placings an ocean apart. The disagreement is the
             * answer and cropping would hide half of it, so the
             * window opens to the whole world and the widget draws
             * what the pane draws.
             */
            $VIEW_W = 360;
            $left = 0;
        } else {
            $left = round(min(360 - $VIEW_W, max(
                0,
                (min($xs) + max($xs)) / 2 - $VIEW_W / 2
            )), 1);
        }
        $top = round(min(180 - $VIEW_H, max(
            0,
            (min($ys) + max($ys)) / 2 - $VIEW_H * 0.56
        )), 1);
        ?>
        <?= $this->element('Values/Renderers/world_outline') ?>
        <div class="vp-rw-geo-map">
            <svg class="vp-rw-plot" viewBox="<?= h($left) ?> <?=
                 h($top) ?> <?= h($VIEW_W) ?> <?= h($VIEW_H) ?>"
                 preserveAspectRatio="xMidYMid meet" aria-hidden="true">
                <rect x="0" y="0" width="360" height="180"
                      class="vp-rw-plot-bg"/>
                <use href="#vp-world" x="0" y="0" width="360"
                     height="180"/>
                <?= $this->element('Values/Renderers/geolocation_boxes',
                    array('boxes' => $boxes, 'min' => 4)) ?>
                <?= $this->element('Values/Renderers/geolocation_points',
                    array('points' => $points, 'halo' => 8, 'dot' => 3.5)) ?>
            </svg>
            <?php if ($headline !== null): ?>
                <?php
                /*
                 * On the map rather than above it. The name and the
                 * map say the same thing and stacking them spends two
                 * lines saying it twice; over the map the name is a
                 * caption on a picture, which is what it is.
                 */
                ?>
                <div class="vp-rw-geo-tag" title="<?= h($tagTitle) ?>">
                    <span class="vp-rw-geo-place"><?=
                        h($headline) ?></span>
                    <?php if ($sub !== null): ?>
                        <span class="vp-rw-geo-in"><?= h($sub) ?></span>
                    <?php elseif ($code !== null
                        && $code !== $headline): ?>
                        <span class="vp-rw-geo-in"><?= h($code) ?></span>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if (!$eventScope && !$data['agreed']): ?>
        <?php
        /*
         * Two services placing one address in two cities is the fact a
         * compact widget must not average away — it is the reason to
         * open the full rendering, and without this line the widget
         * shows one of the two answers as though it were the answer.
         */
        ?>
        <div class="vp-rw-note"><?= h(sprintf(
            __('%s placings'),
            count($data['places'])
        )) ?></div>
    <?php elseif ($extentNote !== null && $extentNote !== ''): ?>
        <div class="vp-rw-note"><?= h($extentNote) ?></div>
    <?php endif; ?>
</div>
