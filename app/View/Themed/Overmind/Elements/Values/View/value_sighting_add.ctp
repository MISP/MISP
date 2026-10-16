<?php
/**
 * The write, disabled — and the sentence that says what it would do.
 *
 * `Sighting::saveSightings(false, [$value], ...)` matches either side of
 * a composite — the same identity rule `Value::conditionsFor` states —
 * and writes one row per attribute the caller can reach. On a value page
 * that is a fan-out: one click here
 * becomes as many rows as this value has visible occurrences, across
 * however many events and organisations those sit in.
 *
 * A control with that reach has to state it before it is ever enabled,
 * so the count is the one the write would produce: every occurrence of
 * the value this viewer can see, soft-deleted ones included, because
 * `saveSightings` resolves through `fetchAttributesSimple` and that
 * fetcher does not drop them. It is therefore larger than the number of
 * reports the list beside it can show — `Sighting::listSightings` does
 * drop them — and it is the write's number that this card owes.
 *
 * Lazily loaded from ValuesController::viewSightingAdd.
 *
 * @var array $valueIntelligence
 * @var string $valueB64
 */
/*
 * Three `COUNT(DISTINCT …)` rather than the rows: on `443` that set is
 * 48,255 occurrences, and fetching them to count cost 617 ms.
 */
$fanout = $valueIntelligence['sighting_fanout'];
$visible = $fanout['occurrences'];
$eventCount = $fanout['events'];
$orgCount = $fanout['orgs'];

$noWrites = __(
    'Disabled in this pass — the Value Intelligence page does not write to'
    . ' the database yet.'
);

$buttons = array(
    array(
        'label' => __('Sighting'),
        'icon' => 'misp-icon misp-icon-sighting misp-simple',
        'class' => 'btn-outline-primary',
    ),
    array(
        'label' => __('False positive'),
        'icon' => 'fas fa-thumbs-down',
        'class' => 'btn-outline-dark',
    ),
    array(
        'label' => __('Expiration'),
        'icon' => 'fas fa-hourglass-end',
        'class' => 'btn-outline-dark',
    ),
);
?>
<div class="card shadow-sm mb-3 vp-panel vp-aside"
     style="--vp-panel-color: var(--sighting);">

    <div class="vp-aside-head">
        <span class="misp-icon misp-icon-sighting misp-simple"
              style="color: var(--sighting);"></span>
        <span class="vp-aside-title"><?= __('Report a sighting') ?></span>
        <span class="vp-aside-meta"><?= __('scoped to the value') ?></span>
    </div>

    <div class="p-3 d-flex flex-column gap-2">

        <?php foreach ($buttons as $button): ?>
            <button type="button"
                    class="btn btn-sm <?= h($button['class']) ?> w-100
                           d-flex align-items-center justify-content-center
                           gap-1"
                    disabled
                    title="<?= h($noWrites) ?>">
                <?php if (strpos($button['icon'], 'misp-icon') === 0): ?>
                    <span class="<?= h($button['icon']) ?>"></span>
                <?php else: ?>
                    <i class="<?= h($button['icon']) ?>"></i>
                <?php endif; ?>
                <?= h($button['label']) ?>
            </button>
        <?php endforeach; ?>

        <?php if ($visible > 0): ?>
            <p class="vp-aside-note">
                <?= h(sprintf(
                    __('Scoped to the value. One row is written to each of'
                        . ' the %1$s you can see, across %2$s and %3$s.'),
                    __n(
                        '%s occurrence',
                        '%s occurrences',
                        $visible,
                        $visible
                    ),
                    __n(
                        '%s event',
                        '%s events',
                        $eventCount,
                        $eventCount
                    ),
                    __n(
                        '%s organisation',
                        '%s organisations',
                        $orgCount,
                        $orgCount
                    )
                )) ?>
            </p>
        <?php else: ?>
            <?php
            /*
             * Still rendered, still disabled, and now with the reason
             * that will outlast this pass: with no occurrence to attach
             * a sighting to there is nothing for the write to fan out
             * across, so this control stays dead even once the page
             * writes.
             */
            ?>
            <p class="vp-aside-note">
                <?= h(__(
                    'Nothing to attach a sighting to. A sighting is filed'
                    . ' against an attribute, and no occurrence of this'
                    . ' value is visible to you.'
                )) ?>
            </p>
        <?php endif; ?>

    </div>

</div>
