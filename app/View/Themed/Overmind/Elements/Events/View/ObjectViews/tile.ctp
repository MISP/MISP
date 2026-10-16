<?php
/**
 * One tile of the object views shelf: what it is about and the renderer's
 * compact drawing. Its panel (the full drawing, the objects it was drawn
 * from, the way to the Objects tab) waits in a template the script moves
 * under the tile's line when it opens.
 *
 * @var array $shape
 * @var array $drawing
 * @var array $subject kind (shape|named|own|neighbour|none), text, tag,
 *            ref, mono, title
 * @var string $position where the tile sits among its own ("3 of 8 hosts")
 * @var int $eventId the event being viewed
 * @var int[] $eventIds the events the shelf drew from
 * @var array $origins uuid => object_id, event_id, template, label
 * @var array $map the view model's `map`
 * @var callable $label shape id => heading
 * @var string|null $sharedTag the template every tile of the bay names
 */
$each = $shape['use'] === 'each';
$none = $subject['kind'] === 'none';

$foreign = array();
foreach ($drawing['origins'] as $uuid) {
    if (isset($origins[$uuid]) && (int)$origins[$uuid]['event_id'] !== $eventId) {
        $foreign[(int)$origins[$uuid]['event_id']] = true;
    }
}
if (isset($drawing['neighbour'])
    && (int)$drawing['neighbour']['event_id'] !== $eventId
) {
    $foreign[(int)$drawing['neighbour']['event_id']] = true;
}
ksort($foreign);
$foreign = array_keys($foreign);

if (!$each) {
    $name = $label($shape['shape']);
} elseif ($none) {
    $name = $subject['title'];
} else {
    $name = $subject['text'];
}
$aria = ($each ? $name . ', ' . $label($shape['shape']) : $name)
    . implode('', array_map(function ($id) {
        return ', ' . sprintf(__('from event %s'), $id);
    }, $foreign));

$scope = array(
    'event_id' => $eventId,
    'origins' => $origins,
    'baseurl' => $baseurl,
    'link' => false,
);
?>
<div class="eov-tile<?= $none ? ' is-none' : '' ?>" role="button"
     tabindex="0" aria-expanded="false" aria-controls="eov-panel"
     aria-label="<?= h($aria) ?>" data-td-tile
     data-td-name="<?= h($name) ?>"
     data-td-pos="<?= h($position) ?>">
    <?php if ($each): ?>
        <?php
        $tag = $sharedTag === null ? $subject['tag'] : null;
        $title = $none ? $subject['title']
            : ($subject['tag'] !== null ? $subject['tag'] . ' ' : '')
                . $subject['text'];
        $text = $none ? $subject['text'] : EventObjectViewsTool::shorten(
            $subject['text'],
            16 - ($tag !== null ? 5 : 0)
        );
        ?>
        <div class="eov-tl" title="<?= h($title) ?>">
            <?php if ($none): ?>
                <i class="far fa-circle-dot" aria-hidden="true"></i>
            <?php endif; ?>
            <?php if ($tag !== null): ?>
                <span class="eov-tl-kind"><?= h($tag) ?></span>
            <?php endif; ?>
            <span class="eov-tl-text<?= $subject['mono']
                ? ' eov-mono' : '' ?>"><?= h($text) ?></span>
        </div>
    <?php endif; ?>
    <div class="eov-draw"><?php
        $this->set('vpEventScope', $scope);
        echo $this->element($shape['compact'], array(
            'data' => $drawing['data'],
        ));
    ?></div>
    <?php if (!$each): ?>
        <div class="eov-foot">
            <?php
            $parts = array();
            $titles = array();
            foreach ($shape['templates'] as $template => $counts) {
                $titles[] = $counts['total'] . ' ' . $template;
                $mono = '<span class="eov-mono">' . h($template) . '</span>';
                if ($counts['read'] < $counts['total']) {
                    $parts[] = '<span class="eov-gread">' . sprintf(
                        h(__('%1$s of %2$s %3$s')),
                        h(number_format($counts['read'])),
                        h(number_format($counts['total'])),
                        $mono
                    ) . '</span>';
                } else {
                    $parts[] = h(number_format($counts['total'])) . ' ' . $mono;
                }
            }
            ?>
            <span class="eov-foot-t" title="<?= h(implode(', ', $titles)) ?>"><?=
                implode(' · ', $parts) ?></span>
            <?php foreach ($foreign as $id): ?>
                <?= $this->element('Events/View/ObjectViews/event_badge', array(
                    'eventId' => $id,
                    'link' => false,
                )) ?>
            <?php endforeach; ?>
        </div>
    <?php else: ?>
        <?php foreach ($foreign as $id): ?>
            <?= $this->element('Events/View/ObjectViews/event_badge', array(
                'eventId' => $id,
                'link' => false,
                'corner' => true,
            )) ?>
        <?php endforeach; ?>
    <?php endif; ?>
    <template data-td-panel>
        <div class="td-head">
            <div class="td-titles">
                <div class="td-kicker"><b><?= h($each
                    ? $label($shape['shape'])
                    : __('Across the event')) ?></b> — <?=
                    h($shape['description']) ?></div>
                <?php
                $titleClass = 'td-title'
                    . ($subject['mono'] ? ' eov-mono' : '')
                    . ($none ? ' is-none' : '');
                ?>
                <h3 class="<?= $titleClass ?>" tabindex="-1">
                    <?php if ($subject['kind'] === 'neighbour'
                        || $subject['kind'] === 'own'): ?>
                        <span class="td-title-kind"><?= h(
                            $subject['kind'] === 'neighbour'
                                ? sprintf(__('%1$s on %2$s'),
                                    ucfirst($shape['words']['one']),
                                    $subject['tag'])
                                : ucfirst($shape['words']['one'])
                        ) ?></span>
                    <?php endif; ?>
                    <?= h($each ? ($none ? $subject['title'] : $subject['text'])
                        : $label($shape['shape'])) ?>
                    <?php foreach ($foreign as $id): ?>
                        <?= $this->element('Events/View/ObjectViews/event_badge',
                            array('eventId' => $id,
                                'text' => sprintf(__('from #%s'), $id))) ?>
                    <?php endforeach; ?>
                </h3>
            </div>
            <div data-td-stepper></div>
            <button type="button" class="td-close" data-td-close
                    aria-label="<?= h(__('Close (Esc)')) ?>"
                    title="<?= h(__('Close (Esc)')) ?>">
                <i class="fas fa-xmark" aria-hidden="true"></i>
            </button>
        </div>
        <div class="td-body">
            <div class="td-draw">
                <?php
                $scope['link'] = true;
                $this->set('vpEventScope', $scope);
                $geo = $shape['shape'] === 'geolocation';
                ?>
                <?php if ($geo && !empty($map['tiles'])): ?>
                    <?= $this->element('Events/View/ObjectViews/map', array(
                        'drawing' => $drawing,
                        'map' => $map,
                        'origins' => $origins,
                    )) ?>
                <?php else: ?>
                    <?= $this->element($shape['full'], array(
                        'data' => $drawing['data'],
                    )) ?>
                    <?php if ($geo && !empty($map['files'])): ?>
                        <?= $this->element('Events/View/ObjectViews/map_files',
                            array('map' => $map, 'origins' => $origins)) ?>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <?= $this->element('Events/View/ObjectViews/aside', array(
                'shape' => $shape,
                'drawing' => $drawing,
                'subject' => $subject,
                'eventId' => $eventId,
                'eventIds' => $eventIds,
                'origins' => $origins,
            )) ?>
        </div>
    </template>
</div>
