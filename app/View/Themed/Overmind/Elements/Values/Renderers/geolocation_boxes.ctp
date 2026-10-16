<?php
/**
 * Areas on the world outline, in its equirectangular units (x is
 * longitude + 180, y is 90 - latitude). A city-sized box is a fraction of
 * a pixel at world scale, so each side is at least `min` units, kept
 * centred on the box.
 *
 * @var array $boxes [[minLat, minLon, maxLat, maxLon], …]
 * @var float $min
 */
foreach ($boxes as $box) {
    $x = $box[1] + 180;
    $y = 90 - $box[2];
    $w = $box[3] - $box[1];
    $hgt = $box[2] - $box[0];
    if ($w < $min) {
        $x -= ($min - $w) / 2;
        $w = $min;
    }
    if ($hgt < $min) {
        $y -= ($min - $hgt) / 2;
        $hgt = $min;
    }
    printf(
        '<rect x="%s" y="%s" width="%s" height="%s" class="vp-rw-plot-area"/>',
        round($x, 2),
        round($y, 2),
        round($w, 2),
        round($hgt, 2)
    );
}
