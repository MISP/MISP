<?php
/**
 * Points on the world outline, in its equirectangular units (x is
 * longitude + 180, y is 90 - latitude). A point whose accuracy radius
 * reaches past its halo is ringed by that area instead: a country-level
 * answer sits at the country's centre and could be anywhere in it.
 * Rings first, then every dot, so no ring covers another point.
 *
 * @var array $points
 * @var float $halo
 * @var float $dot
 */
$at = function ($point) {
    return array(round($point['lon'] + 180, 2), round(90 - $point['lat'], 2));
};
foreach ($points as $point) {
    list($cx, $cy) = $at($point);
    $reach = $point['reach'] ?? null;
    if ($reach !== null && $reach[1] > $halo) {
        printf(
            '<ellipse cx="%s" cy="%s" rx="%s" ry="%s" class="vp-rw-plot-reach"/>',
            $cx,
            $cy,
            $reach[0],
            $reach[1]
        );
    } else {
        printf(
            '<circle cx="%s" cy="%s" r="%s" class="vp-rw-plot-halo"/>',
            $cx,
            $cy,
            $halo
        );
    }
}
foreach ($points as $point) {
    list($cx, $cy) = $at($point);
    printf(
        '<circle cx="%s" cy="%s" r="%s" class="vp-rw-plot-dot"/>',
        $cx,
        $cy,
        $dot
    );
}
