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

$spec = array('tileUrl' => $map['tile_url'], 'points' => array(), 'files' => array());
foreach ($data['points'] as $point) {
    $origin = $origins[$point['module']] ?? null;
    $spec['points'][] = array(
        'lat' => (float)$point['lat'],
        'lon' => (float)$point['lon'],
        'popup' => array_values(array_filter(array(
            $name($origin),
            implode(', ', array_filter(array($point['city'], $point['country']))),
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
<ul class="eov-legend" aria-label="<?= h(__('On the map')) ?>">
    <?php foreach ($data['points'] as $point): ?>
        <?php $origin = $origins[$point['module']] ?? null; ?>
        <li>
            <span class="eov-key eov-key-point"></span>
            <span class="eov-lg-name"><?= h($name($origin)) ?></span>
            <span class="eov-lg-meta"><?= h(implode(' · ', array_filter(array(
                implode(', ', array_filter(array($point['city'], $point['country']))),
                $point['lat'] . ', ' . $point['lon'],
            )))) ?><?= $origin === null ? '' : ' · ' . $link($origin,
                $origin['template'] . ' #' . $origin['object_id']) ?></span>
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
        </li>
    <?php endforeach; ?>
</ul>
