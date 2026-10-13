<?php
/**
 * Beside an open drawing: what it is about when that is another object,
 * the objects it was drawn from, and the way to the Objects tab.
 *
 * @var array $shape
 * @var array $drawing
 * @var array $subject see the shelf's subjectOf
 * @var int $eventId
 * @var array $origins
 */
App::uses('EventObjectViewsTool', 'Tools/EventOverview');

$SHOWN = 8;
$objectIcon = '<i class="misp-icon misp-icon-object misp-simple"'
    . ' aria-hidden="true"></i>';

// How many drawn objects of the whole shape carry each template.
$drawnByTemplate = array();
foreach ($shape['drawings'] as $one) {
    foreach ($one['origins'] as $uuid) {
        if (isset($origins[$uuid])) {
            $template = $origins[$uuid]['template'];
            $drawnByTemplate[$template] = ($drawnByTemplate[$template] ?? 0) + 1;
        }
    }
}
?>
<aside class="eov-aside" aria-label="<?= h(__('Where this comes from')) ?>">
    <?php if ($subject['ref'] !== null): ?>
        <?php $ref = $subject['ref']; ?>
        <section>
            <h4><?= h($subject['kind'] === 'neighbour'
                ? __('About') : __('This object')) ?></h4>
            <div class="eov-about">
                <div>
                    <?= $objectIcon ?>
                    <a href="<?= h($baseurl . '/objects/view/'
                        . (int)$ref['object_id']) ?>"><?=
                        h($ref['template'] . ' #' . $ref['object_id']) ?></a>
                    <?php if ((int)$ref['event_id'] !== $eventId): ?>
                        <?= $this->element('Events/View/ObjectViews/event_badge',
                            array('eventId' => $ref['event_id'])) ?>
                    <?php endif; ?>
                </div>
                <?php if (($ref['label'] ?? null) !== null): ?>
                    <span class="eov-about-v"><?= h($ref['label']) ?></span>
                <?php endif; ?>
            </div>
        </section>
    <?php endif; ?>

    <section>
        <?php $count = count($drawing['origins']); ?>
        <h4><?= h(sprintf(__n('Drawn from %s object', 'Drawn from %s objects',
            $count), number_format($count))) ?></h4>
        <ul class="eov-olist">
            <?php foreach (array_slice($drawing['origins'], 0, $SHOWN) as $uuid): ?>
                <?php
                if (!isset($origins[$uuid])) {
                    continue;
                }
                $origin = $origins[$uuid];
                $code = $origin['label'] !== null
                    && preg_match('/^\S+$/u', $origin['label']);
                $text = $origin['label'] === null ? '#' . $origin['object_id']
                    : ($code ? EventObjectViewsTool::shorten($origin['label'], 24)
                        : $origin['label']);
                ?>
                <li>
                    <?= $objectIcon ?>
                    <a class="eov-olink<?= $code ? ' eov-mono' : '' ?>"
                       href="<?= h($baseurl . '/objects/view/'
                           . (int)$origin['object_id']) ?>"
                       title="<?= h($origin['template'] . ' #'
                           . $origin['object_id']
                           . ($origin['label'] !== null
                               ? ' · ' . $origin['label'] : '')) ?>"><?=
                        h($text) ?></a>
                    <span class="eov-ot"><?= h($origin['template']) ?></span>
                    <?php if ((int)$origin['event_id'] !== $eventId): ?>
                        <?= $this->element('Events/View/ObjectViews/event_badge',
                            array('eventId' => $origin['event_id'])) ?>
                    <?php endif; ?>
                </li>
            <?php endforeach; ?>
        </ul>
        <?php if ($count > $SHOWN): ?>
            <p class="eov-more-note"><?= h(sprintf(
                __('and %s more — every one is in the Objects tab'),
                number_format($count - $SHOWN)
            )) ?></p>
        <?php endif; ?>
    </section>

    <section>
        <h4><?= h(__('In the Objects tab')) ?></h4>
        <div class="eov-objs">
            <?php foreach ($shape['templates'] as $template => $counts): ?>
                <?= $this->element('Events/View/ObjectViews/objects_button', array(
                    'template' => $template,
                    'total' => $counts['total'],
                    'long' => true,
                )) ?>
                <?php
                $notes = array();
                if ($counts['read'] < $counts['total']) {
                    $notes[] = sprintf(__('%1$s of %2$s read'),
                        number_format($counts['read']),
                        number_format($counts['total']));
                }
                if (empty($drawnByTemplate[$template])) {
                    $notes[] = __('none of them drawn');
                }
                ?>
                <?php if (!empty($notes)): ?>
                    <div class="eov-objs-note"><?=
                        h(implode(' · ', $notes)) ?></div>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
        <?php if ($shape['use'] === 'each'
            && $shape['subjects']['drawn'] < $shape['subjects']['total']): ?>
            <p class="eov-more-note"><?= sprintf(
                h(__('%1$s of the %2$s %3$s read are drawn on the shelf.')),
                '<b>' . h(number_format($shape['subjects']['drawn'])) . '</b>',
                h(number_format($shape['subjects']['total'])),
                h($shape['words']['many'])
            ) ?></p>
        <?php endif; ?>
    </section>
</aside>
