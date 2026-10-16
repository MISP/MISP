<?php
/**
 * What the event's objects describe, drawn by the Value Intelligence
 * renderers: one card of tiles under the Context/Inventory row. A drawing
 * about the whole event is one wide tile; a drawing per subject is a bay of
 * small tiles, one each. A tile opens in place (event-object-views.js),
 * which is where the full drawing, its objects and the map are. Nothing at
 * all when nothing is drawable.
 *
 * @var array $views EventObjectViewsTool::views()
 * @var array $event
 */
App::uses('EventObjectViewsTool', 'Tools/EventOverview');

$shapes = array_values(array_filter($views['shapes'], function ($shape) {
    return !empty($shape['drawings']);
}));
if (empty($shapes)) {
    return;
}
$eventId = (int)$event['Event']['id'];
$origins = is_array($views['origins']) ? $views['origins'] : array();
$label = function ($shape) {
    return ucfirst(str_replace('-', ' ', $shape));
};

/*
 * What one tile is about. A drawing per subject names it; one whose
 * object names nothing is about that object, or about the object it
 * references (a report about a file); a group that names nothing says so.
 */
$subjectOf = function (array $shape, array $drawing) use ($origins) {
    $words = $shape['words'] ?? array();
    if ($shape['use'] !== 'each') {
        return array('kind' => 'shape', 'text' => null, 'tag' => null,
            'ref' => null, 'mono' => false);
    }
    $kind = $drawing['subject_kind'] ?? ($drawing['subject'] === null
        ? 'own' : 'named');
    if ($kind === 'named') {
        return array('kind' => 'named', 'text' => (string)$drawing['subject'],
            'tag' => null, 'ref' => null, 'mono' => true);
    }
    if ($kind === 'none') {
        return array('kind' => 'none', 'text' => $words['none'] ?? '',
            'title' => $words['none_title'] ?? '', 'tag' => null,
            'ref' => null, 'mono' => false);
    }
    $ref = $drawing['neighbour']
        ?? ($origins[$drawing['origins'][0] ?? ''] ?? null);
    if ($ref === null) {
        return array('kind' => 'none', 'text' => $words['none'] ?? '',
            'title' => $words['none_title'] ?? '', 'tag' => null,
            'ref' => null, 'mono' => false);
    }
    return array(
        'kind' => isset($drawing['neighbour']) ? 'neighbour' : 'own',
        'text' => $ref['label'] ?? ($ref['template'] . ' #' . $ref['object_id']),
        'tag' => $ref['template'],
        'ref' => $ref,
        'mono' => ($ref['label'] ?? null) !== null,
    );
};

$sets = array();
$eaches = array();
foreach ($shapes as $shape) {
    if ($shape['use'] === 'each') {
        $eaches[] = $shape;
    } else {
        $sets[] = $shape;
    }
}
$setCount = count($sets);

$eventIds = array();
foreach ($origins as $origin) {
    $eventIds[(int)$origin['event_id']] = true;
}
ksort($eventIds);
$eventIds = array_keys($eventIds);
$objectCount = count($origins);

$strings = $this->element('TileDrawer/strings', array('extra' => array(
    'shown' => __('%1$s of %2$s shown'),
    'allShown' => __('all %s shown'),
    'fitAll' => __('Show everything on the map'),
)));
?>
<?= $this->element('Values/Renderers/world_outline') ?>
<section class="card shadow-sm mb-3 eov-shelf td-host" data-eov-shelf
         data-td-strings="<?= h($strings) ?>"
         aria-labelledby="eov-title">
    <div class="eov-head">
        <div class="misp-icon-tile eov-head-tile"
             style="--tile:var(--object);--tile-bg:color-mix(in srgb, var(--object) 12%, transparent);">
            <i class="fas fa-shapes" aria-hidden="true"></i>
        </div>
        <div class="eov-head-text">
            <h2 class="eov-title" id="eov-title"><?=
                h(__('What the objects describe')) ?></h2>
            <div class="eov-sub"><?php
                $count = '<b>' . h(number_format($objectCount)) . '</b>';
                if (count($eventIds) > 1) {
                    $named = array_map(function ($id) {
                        return '<b>#' . (int)$id . '</b>';
                    }, $eventIds);
                    $last = array_pop($named);
                    echo sprintf(
                        h(__n('Drawn from %1$s object across events %2$s',
                            'Drawn from %1$s objects across events %2$s',
                            $objectCount)),
                        $count,
                        implode(', ', $named) . ' ' . h(__('and')) . ' ' . $last
                    );
                } else {
                    echo sprintf(h(__n('Drawn from %s object of this event',
                        'Drawn from %s objects of this event', $objectCount)),
                        $count);
                }
                echo ' · ' . h(__('open a tile to see all of it'));
            ?></div>
        </div>
    </div>
    <div class="eov-tray">
        <?php foreach ($sets as $s => $shape): ?>
            <div class="eov-group eov-group-set" role="group"
                 aria-label="<?= h($label($shape['shape'])) ?>">
                <div class="eov-ghead">
                    <span class="eov-gname"
                          title="<?= h($shape['description']) ?>"><?=
                        h($label($shape['shape'])) ?></span>
                    <span class="eov-grule"></span>
                </div>
                <?= $this->element('Events/View/ObjectViews/tile', array(
                    'shape' => $shape,
                    'drawing' => $shape['drawings'][0],
                    'subject' => $subjectOf($shape, $shape['drawings'][0]),
                    'position' => sprintf(
                        __('%1$s of %2$s across the event'),
                        $s + 1,
                        $setCount
                    ),
                    'eventId' => $eventId,
                    'eventIds' => $eventIds,
                    'origins' => $origins,
                    'map' => $views['map'],
                    'label' => $label,
                    'sharedTag' => null,
                )) ?>
            </div>
        <?php endforeach; ?>

        <?php foreach ($eaches as $shape): ?>
            <?php
            $words = $shape['words'];
            $subjects = array();
            foreach ($shape['drawings'] as $drawing) {
                $subjects[] = $subjectOf($shape, $drawing);
            }
            // The template every subject is named after, when they share
            // one: said once in the heading instead of on every tile.
            $tags = array_column($subjects, 'tag');
            $sharedTag = count(array_filter($tags)) === count($subjects)
                && count(array_unique($tags)) === 1 ? $tags[0] : null;
            $total = $shape['subjects']['total'];
            $drawn = $shape['subjects']['drawn'];
            $nones = count(array_filter($subjects, function ($one) {
                return $one['kind'] === 'none';
            }));
            $about = $sharedTag === null ? ''
                : sprintf(__(', each about one %s'), $sharedTag);
            ?>
            <div class="eov-group eov-group-each" role="group"
                 aria-label="<?= h($label($shape['shape'])) ?>"
                 data-eov-each>
                <div class="eov-ghead">
                    <span class="eov-gname"
                          title="<?= h($shape['description']) ?>"><?=
                        h($label($shape['shape'])) ?></span>
                    <span class="eov-gcount"><?php
                        if ($drawn < $total) {
                            echo sprintf(
                                h(__('%1$s of %2$s %3$s drawn')),
                                '<b>' . h(number_format($drawn)) . '</b>',
                                h(number_format($total)),
                                h($total === 1 ? $words['one'] : $words['many'])
                            ) . h($about);
                        } else {
                            $named = $total - $nones;
                            if ($named > 0) {
                                echo '<b>' . h(number_format($named)) . '</b> '
                                    . h($named === 1 ? $words['one']
                                        : $words['many']) . h($about);
                            }
                            if ($named > 0 && $nones > 0) {
                                echo ' · ';
                            }
                            if ($nones > 0) {
                                echo sprintf(
                                    h(__n('%s group', '%s groups', $nones)),
                                    '<b>' . h(number_format($nones)) . '</b>'
                                ) . ' ' . h($words['none_group']);
                            }
                        }
                    ?></span>
                    <?php foreach ($shape['templates'] as $template => $counts): ?>
                        <?php if ($counts['read'] < $counts['total']): ?>
                            <span class="eov-gread"><?= sprintf(
                                h(__('%1$s of %2$s %3$s read')),
                                h(number_format($counts['read'])),
                                h(number_format($counts['total'])),
                                '<span class="eov-mono">' . h($template)
                                    . '</span>'
                            ) ?></span>
                        <?php endif; ?>
                    <?php endforeach; ?>
                    <span class="eov-grule"></span>
                    <span class="eov-glinks">
                        <?php foreach ($shape['templates'] as $template => $counts): ?>
                            <?= $this->element(
                                'Events/View/ObjectViews/objects_button',
                                array('template' => $template,
                                    'total' => $counts['total'])
                            ) ?>
                        <?php endforeach; ?>
                    </span>
                </div>
                <?php foreach ($shape['drawings'] as $i => $drawing): ?>
                    <?= $this->element('Events/View/ObjectViews/tile', array(
                        'shape' => $shape,
                        'drawing' => $drawing,
                        'subject' => $subjects[$i],
                            'position' => $subjects[$i]['kind'] === 'none'
                            && $drawn === 1
                            ? sprintf(__('%1$s of %2$s'), 1, 1)
                            : sprintf(
                                __('%1$s of %2$s %3$s'),
                                $i + 1,
                                number_format($drawn),
                                $drawn === 1 ? $words['one'] : $words['many']
                            ),
                        'eventId' => $eventId,
                        'eventIds' => $eventIds,
                        'origins' => $origins,
                        'map' => $views['map'],
                        'label' => $label,
                        'sharedTag' => $sharedTag,
                    )) ?>
                <?php endforeach; ?>
                <button type="button" class="eov-more" data-eov-more
                        hidden></button>
            </div>
        <?php endforeach; ?>
    </div>
</section>
<?php $this->set('vpEventScope', null); ?>
