<?php
/**
 * Extension relationships of an event, and the switch between the atomic view
 * and the extended / extending ones.
 *
 * The block's own label is the current mode — "Atomic view" until one of the
 * two switches on its right is used — and the related events are laid out as
 * event badges, three to a line: the events extending this one first, the event
 * it extends on the line after. The direction is carried by that order and by
 * each cell's tooltip rather than by a heading, so the two groups read as one
 * list of related events.
 *
 * `Extends` (the event this one extends) and `ExtendedBy` (the events that
 * extend it) are both attached by EventsController::__enrichEvent(); the block
 * renders nothing when neither is set, so it can be dropped into the general
 * card unconditionally.
 *
 * Parameters:
 *   data  full event array, as handed to the view (needs Event.id and the two
 *         extension keys)
 *
 * Read from the view: $extended, $extending, $extensionEvents
 */
$extEvent = $data['Event'] ?? [];
$parent = $extEvent['Extends'] ?? null;
$children = $extEvent['ExtendedBy'] ?? [];
if (empty($parent) && empty($children)) {
    return;
}

$extEventId = (int)($extEvent['id'] ?? 0);
$isExtended = !empty($extended);
$isExtending = !empty($extending);
$extensionEvents = $extensionEvents ?? [];

$viewUrl = function ($extended, $extending) use ($baseurl, $extEventId) {
    return $baseurl . '/events/view2/' . $extEventId
        . ($extended ? '/extended:1' : '')
        . ($extending ? '/extending:1' : '');
};

// The mode names the block. Its glyph is the one the origin badges carry, so a
// tinted row and the switch that brought it in look related.
if ($isExtended && $isExtending) {
    $currentIcon = 'fas fa-code-compare';
    $currentLabel = __('Extended and extending view');
} elseif ($isExtended) {
    $currentIcon = 'fas fa-code-branch';
    $currentLabel = __('Extended view');
} elseif ($isExtending) {
    $currentIcon = 'fas fa-code-merge';
    $currentLabel = __('Extending view');
} else {
    $currentIcon = 'fas fa-atom';
    $currentLabel = __('Atomic view');
}

/**
 * One related event, as the canonical event badge: the direction of the
 * relationship as the eyebrow glyph, and — only while the event is actually
 * merged into the view — its origin colour on the card's border and
 * background, so the cell and the rows it brought in read as one thing.
 * Outside that the cell stays neutral rather than promising a tint the tables
 * are not showing.
 */
$eventCell = function ($eventId, $info, $org, $icon, $title)
    use ($baseurl, $extensionEvents) {
    $palette = $extensionEvents[(int)$eventId]['palette'] ?? null;
    $accent = $palette === null ? [] : [
        'headerBg' => $palette['badgeBg'],
        'bodyBg' => $palette['sectionBg'],
        'border' => $palette['badgeBorder'],
        'text' => $palette['headerText'],
    ];
    ?>
    <div class="col">
        <div class="h-100" data-bs-toggle="tooltip" title="<?= h($title) ?>">
            <?= $this->element('genericElementsBS5/Badges/event', [
                'id' => $eventId,
                'name' => $info,
                'url' => $baseurl . '/events/view2/' . (int)$eventId,
                'org' => $org,
                'icon' => $icon,
                'accent' => $accent,
            ]) ?>
        </div>
    </div>
    <?php
};
?>

<div class="col-12">
    <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
        <div class="text-muted small text-uppercase fw-bold d-inline-flex align-items-center gap-1">
            <i class="<?= h($currentIcon) ?>"></i>
            <?= h($currentLabel) ?>
        </div>

        <div class="d-flex gap-2">
            <?php if (!empty($children)):
                $extendedTitle = $isExtended
                    ? __('Switch back to atomic view')
                    : __('Switch to extended view');
            ?>
                <a href="<?= h($viewUrl(!$isExtended, $isExtending)) ?>"
                   class="btn btn-sm py-0 px-2 lh-1 <?= $isExtended ? 'btn-primary' : 'btn-outline-primary' ?>"
                   data-bs-toggle="tooltip"
                   title="<?= h($extendedTitle) ?>"
                   aria-label="<?= h($extendedTitle) ?>">
                    <i class="fas fa-code-branch"></i>
                </a>
            <?php endif; ?>

            <?php if (is_array($parent)):
                $extendingTitle = $isExtending
                    ? __('Switch back to atomic view')
                    : __('Switch to extending view');
            ?>
                <a href="<?= h($viewUrl($isExtended, !$isExtending)) ?>"
                   class="btn btn-sm py-0 px-2 lh-1 <?= $isExtending ? 'btn-primary' : 'btn-outline-primary' ?>"
                   data-bs-toggle="tooltip"
                   title="<?= h($extendingTitle) ?>"
                   aria-label="<?= h($extendingTitle) ?>">
                    <i class="fas fa-code-merge"></i>
                </a>
            <?php endif; ?>
        </div>
    </div>

    <div class="d-flex flex-column gap-2">

        <?php if (!empty($children)): ?>
            <div class="row row-cols-1 row-cols-sm-2 row-cols-lg-3 g-2">
                <?php foreach ($children as $child): ?>
                    <?php $eventCell(
                        $child['id'],
                        (string)$child['info'],
                        $child['Orgc'] ?? [],
                        'fas fa-code-branch',
                        __('An event that extends this one')
                    ); ?>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($parent)): ?>
            <div class="row row-cols-1 row-cols-sm-2 row-cols-lg-3 g-2">
                <?php if (is_array($parent)): ?>
                    <?php $eventCell(
                        $parent['id'],
                        (string)$parent['info'],
                        $parent['Orgc'] ?? [],
                        'fas fa-code-merge',
                        __('The event this one extends')
                    ); ?>
                <?php else: ?>
                    <div class="col">
                        <div class="h-100 rounded border d-flex align-items-center gap-2 px-2 py-1"
                             data-bs-toggle="tooltip"
                             title="<?= __('The event this one extends') ?>">
                            <i class="fas fa-code-merge text-muted"></i>
                            <span class="font-monospace small text-truncate">
                                <?= h($parent) ?>
                            </span>
                            <span class="ms-auto badge text-bg-light flex-shrink-0">
                                <?= __('Not accessible to you') ?>
                            </span>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

    </div>
</div>
