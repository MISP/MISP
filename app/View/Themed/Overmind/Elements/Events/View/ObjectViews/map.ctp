<?php
/**
 * One map of every place, area and track of the event, drawn by
 * ObjectMap.drawAll() when the panel opens: the files are fetched then,
 * and each legend line says what it held.
 *
 * @var array $drawing the geolocation drawing
 * @var array $map the view model's `map` (files, tiles, tile_url)
 * @var array $origins
 */
$data = $drawing['data'];
$extents = array();
foreach ($data['extents'] ?? array() as $extent) {
    $extents[$extent['module']] = $extent;
}
$name = function ($origin) {
    return $origin === null ? __('an object')
        : ($origin['label'] ?? ($origin['template'] . ' #' . $origin['object_id']));
};
$link = function ($origin, $text) use ($baseurl) {
    return $origin === null ? '' : sprintf('<a href="%s" data-eov-object="%d">%s</a>',
        h($baseurl . '/objects/view/' . (int)$origin['object_id']),
        (int)$origin['object_id'], h($text));
};
$kindOf = function ($template) {
    return $template === 'geojson' ? 'area' : 'track';
};
// With two things or more on the map, each legend line can fit and centre
// the map on its own; a track or area's waits until its file is drawn.
$locatable = count($data['points']) + count($map['files']) > 1;
$locate = function ($key, $what, $ready) use ($locatable) {
    if (!$locatable) {
        return '';
    }
    return sprintf(
        '<button type="button" class="eov-locate" data-eov-locate="%s" title="%s" aria-label="%s"%s>'
            . '<i class="fas fa-location-crosshairs" aria-hidden="true"></i></button>',
        h($key),
        h(__('Fit and centre the map on this')),
        h(sprintf(__('Fit and centre the map on %s'), $what)),
        $ready ? '' : ' disabled'
    );
};

$within = function ($point) {
    if (empty($point['radius'])) {
        return null;
    }
    $km = number_format($point['radius'], $point['radius'] < 10 ? 1 : 0);
    return '±' . sprintf(__('%s km'), preg_replace('/\.0$/', '', $km));
};

$spec = array('tileUrl' => $map['tile_url'], 'points' => array(), 'files' => array());
foreach (array_values($data['points']) as $point) {
    $origin = $origins[$point['module']] ?? null;
    $spec['points'][] = array(
        'lat' => (float)$point['lat'],
        'lon' => (float)$point['lon'],
        'radius' => $point['radius'] ?? null,
        'popup' => array_values(array_filter(array(
            $name($origin),
            implode(', ', array_filter(array($point['city'], $point['country']))),
            $within($point),
        ))),
    );
}
foreach ($map['files'] as $file) {
    $spec['files'][] = array(
        'attachment' => (int)$file['attachment'],
        'kind' => $kindOf($file['template']),
    );
}
?>
<div class="eov-map" role="img" data-eov-map="<?= h(json_encode($spec)) ?>"
     aria-label="<?= h(__('Map of every place, area and track in this event')) ?>"></div>
<ul class="eov-legend<?= $locatable ? ' has-locate' : '' ?>" aria-label="<?= h(__('On the map')) ?>">
    <?php foreach (array_values($data['points']) as $i => $point): ?>
        <?php $origin = $origins[$point['module']] ?? null; ?>
        <li>
            <span class="eov-key eov-key-point"></span>
            <span class="eov-lg-name"><?= h($name($origin)) ?></span>
            <span class="eov-lg-meta"><?= h(implode(' · ', array_filter(array(
                implode(', ', array_filter(array($point['city'], $point['country']))),
                $point['lat'] . ', ' . $point['lon'],
                $within($point),
            )))) ?><?= $origin === null ? '' : ' · ' . $link($origin,
                $origin['template'] . ' #' . $origin['object_id']) ?></span>
            <?= $locate('point:' . $i, $name($origin), true) ?>
        </li>
    <?php endforeach; ?>
    <?php foreach ($map['files'] as $file): ?>
        <?php
        $origin = $origins[$file['origin']] ?? null;
        $extent = $extents[$file['origin']] ?? null;
        $when = null;
        if ($extent !== null && $extent['start'] !== null) {
            $when = gmdate('Y-m-d H:i', $extent['start']) . ' → '
                . ($extent['end'] === null ? '?' : gmdate('H:i', $extent['end']))
                . ' UTC';
        }
        ?>
        <li>
            <span class="eov-key eov-key-<?= h($kindOf($file['template'])) ?>"></span>
            <span class="eov-lg-name" title="<?= h($file['name']) ?>"><?=
                h($file['name']) ?></span>
            <span class="eov-lg-meta"><?= h($file['template']) ?><?=
                $origin === null ? '' : ' · ' . $link($origin, $name($origin))
                ?><?= $when === null ? '' : ' · ' . h($when) ?> · <a href="<?=
                h($baseurl . '/attributes/download/' . (int)$file['attachment'])
                ?>" download="<?= h($file['name']) ?>"><?= h(__('download'))
                ?></a> · <span data-eov-status="<?= (int)$file['attachment']
                ?>"><?= h(__('loading…')) ?></span></span>
            <?= $locate('file:' . (int)$file['attachment'], $file['name'], false) ?>
        </li>
    <?php endforeach; ?>
</ul>
