<?php
/**
 * The Sightings tab's Report a sighting card: the three kinds of report,
 * in the chart's colours, and what one press would write to (a row on each
 * occurrence of the value the reader can see).
 *
 * The page writes nothing yet, so the buttons are disabled and the card
 * says so in a line rather than only in a tooltip.
 *
 * Lazily loaded from ValuesController::viewSightingAdd.
 *
 * @var array $valueIntelligence
 */
$fanout = $valueIntelligence['sighting_fanout'];
$visible = $fanout['occurrences'];
$eventCount = $fanout['events'];
$orgCount = $fanout['orgs'];
$noWrites = __('Disabled in this pass — the Value Intelligence page does not write to the database yet.');
$buttons = array(
    array('kind' => 'sighting', 'label' => __('Sighting'), 'icon' => 'misp-icon misp-icon-sighting misp-simple'),
    array('kind' => 'fp', 'label' => __('False positive'), 'icon' => 'fas fa-thumbs-down'),
    array('kind' => 'expiration', 'label' => __('Expiration'), 'icon' => 'fas fa-hourglass-end'),
);
?>
<div class="card shadow-sm mb-3 vp-panel vp-aside"
     style="--vp-panel-color: var(--sighting);">
    <div class="vp-aside-head">
        <span class="misp-icon misp-icon-sighting misp-simple" style="color: var(--sighting);"></span>
        <span class="vp-aside-title"><?= __('Report a sighting') ?></span>
        <span class="vp-aside-meta"><?= __('on this value') ?></span>
    </div>
    <div class="p-3 d-flex flex-column gap-2">
        <div class="vp-sight-add" role="group" aria-label="<?= h(__('Report a sighting')) ?>">
            <?php foreach ($buttons as $button): ?>
                <button type="button" class="vp-sight-add-btn is-<?= h($button['kind']) ?>" disabled title="<?= h($noWrites) ?>">
                    <?php if (strpos($button['icon'], 'misp-icon') === 0): ?>
                        <span class="<?= h($button['icon']) ?>" aria-hidden="true"></span>
                    <?php else: ?>
                        <i class="<?= h($button['icon']) ?>" aria-hidden="true"></i>
                    <?php endif; ?>
                    <span><?= h($button['label']) ?></span>
                </button>
            <?php endforeach; ?>
        </div>
        <?php if ($visible > 0): ?>
            <p class="vp-aside-note vp-shelf-note">
                <i class="fas fa-layer-group" aria-hidden="true"></i>
                <span><?= h(sprintf(
                    __('One report on each of the %1$s you can see (%2$s, %3$s).'),
                    __n('%s occurrence', '%s occurrences', $visible, $visible),
                    __n('%s event', '%s events', $eventCount, $eventCount),
                    __n('%s organisation', '%s organisations', $orgCount, $orgCount)
                )) ?></span>
            </p>
        <?php else: ?>
            <p class="vp-aside-note vp-shelf-note">
                <i class="fas fa-circle-info" aria-hidden="true"></i>
                <span><?= h(__('Nothing to attach a sighting to: no occurrence of this value is visible to you.')) ?></span>
            </p>
        <?php endif; ?>
        <p class="vp-aside-note vp-shelf-note">
            <i class="fas fa-lock" aria-hidden="true"></i>
            <span><?= h(__('Not available on this page yet.')) ?></span>
        </p>
    </div>
</div>
