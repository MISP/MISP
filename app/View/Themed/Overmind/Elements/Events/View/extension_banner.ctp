<?php
/**
 * Strip shown above the event tabs while an extended / extending view is on:
 * what is currently merged in, in which colour, and the way back out.
 *
 * Renders nothing in the atomic view.
 *
 * Read from the view: $extended, $extending, $extensionEvents, $event
 */
if (empty($extended) && empty($extending)) {
    return;
}

$bannerEventId = (int)($event['Event']['id'] ?? 0);
$merged = array_filter(
    $extensionEvents ?? [],
    function ($extensionEvent) {
        return $extensionEvent['role'] !== 'self';
    }
);

if (!empty($extended) && !empty($extending)) {
    $modeLabel = __('Extended and extending view');
} elseif (!empty($extended)) {
    $modeLabel = __('Extended view');
} else {
    $modeLabel = __('Extending view');
}
?>

<div class="container-fluid">
    <div class="alert alert-primary d-flex align-items-start gap-3 py-2 px-3 mb-3"
         id="event-extension-banner">
        <i class="fas fa-code-branch mt-1"></i>

        <div class="flex-grow-1">
            <div class="fw-semibold"><?= h($modeLabel) ?></div>
            <div class="small">
                <?= __n(
                    'Attributes, objects, reports, tags and clusters of %s related event are shown alongside this one.',
                    'Attributes, objects, reports, tags and clusters of %s related events are shown alongside this one.',
                    count($merged),
                    count($merged)
                ) ?>
            </div>

            <?php if (!empty($merged)): ?>
                <div class="d-flex flex-wrap gap-2 mt-2">
                    <?php foreach ($merged as $mergedEvent): ?>
                        <?= $this->element('Events/View/extension_origin', [
                            'event_id' => $mergedEvent['id'],
                        ]) ?>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="small fst-italic mt-1">
                    <?= __('No related event is visible to you, so nothing was merged in.') ?>
                </div>
            <?php endif; ?>
        </div>

        <a href="<?= h($baseurl . '/events/view2/' . $bannerEventId) ?>"
           class="btn btn-sm btn-outline-primary flex-shrink-0">
            <i class="fas fa-arrow-rotate-left me-1"></i>
            <?= __('Back to atomic view') ?>
        </a>
    </div>
</div>
