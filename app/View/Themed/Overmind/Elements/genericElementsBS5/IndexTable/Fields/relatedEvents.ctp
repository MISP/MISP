<?php

$isCard    = isset($viewMode) && $viewMode === 'card';

$isEventView = !isset($row['Attribute']);
if ($isEventView) {
    // In event context, $row is already the Attribute array
    $attribute = $row;
    $relatedAttribute = isset($row['RelatedAttribute']) ? $row['RelatedAttribute'] : [];
} else {
    // In global index context, $row contains an 'Attribute' key
    $attribute = isset($row['Attribute']) ? $row['Attribute'] : null;
    $relatedAttribute = isset($row['Event']['RelatedAttribute']) ? $row['Event']['RelatedAttribute'] : [];
}
if (!$attribute || !isset($attribute['id'])) return;
$attrId    = $attribute ? $attribute['id'] : null;

if ($isEventView) {
    $relatedList = isset($attribute['RelatedAttribute']) ? $attribute['RelatedAttribute'] : [];
} else {
    $relatedList = ($relatedAttribute && $attrId && !empty($relatedAttribute[$attrId]))
        ? $relatedAttribute[$attrId]
        : [];
}


if (empty($relatedList)) {
    if (!empty($attribute['correlation_exclusion'])) {
        echo sprintf(
            '<span class="badge text-bg-warning text-dark d-inline-flex align-items-center gap-1"'
            . ' title="%s"><i class="fas fa-ban"></i> %s</span>',
            __('The attribute value matches a correlation exclusion rule.'),
            __('Excluded')
        );
    } elseif (!empty($attribute['over_correlation'])) {
        echo sprintf(
            '<span class="badge text-bg-danger d-inline-flex align-items-center gap-1"'
            . ' title="%s"><i class="fas fa-exclamation-triangle"></i> %s</span>',
            __('The correlation threshold has been exceeded for this value.'),
            __('Overcorrelated')
        );
    }
    return;
}

// Deduplicate by event id
$seen   = [];
$events = [];
foreach ($relatedList as $ra) {
    $eventId = isset($ra['Event']['id']) ? $ra['Event']['id'] : $ra['id'];
    if (!$eventId || isset($seen[$eventId])) continue;
    $seen[$eventId] = true;
    $events[] = [
        'id'    => $eventId,
        'info'  => isset($ra['info'])  ? $ra['info']  : (isset($ra['Event']['info'])  ? $ra['Event']['info']  : ''),
        'org'   => isset($ra['org_id'])? $ra['org_id']: (isset($ra['Event']['org_id'])? $ra['Event']['org_id']: ''),
        'value' => isset($ra['value']) ? $ra['value'] : '',
        'date'  => isset($ra['date'])  ? $ra['date']  : '',
    ];
}

if (empty($events)) return;

$maxVisible = 4;
$total      = count($events);
$overflow   = $total - $maxVisible;
?>

<div class="d-flex flex-wrap align-items-center gap-1">
    <?php foreach ($events as $i => $ev): ?>
        <?php
            $hidden  = ($i >= $maxVisible && $overflow > 0);
            //$isOwn   = !empty($ev['org']) && $ev['org'] == $me['org_id'];
            $tooltip = implode(' | ', array_filter([
                !empty($ev['info'])  ? h($ev['info'])  : null,
                !empty($ev['value']) ? h($ev['value']) : null,
                !empty($ev['date'])  ? h($ev['date'])  : null,
            ]));
        ?>
        <a href="<?= $baseurl ?>/events/view/<?= h($ev['id']) ?>"
           class="badge text-decoration-none bg-primary <?= $hidden ? ' d-none related-event-extra' : '' ?>"
           title="<?= $tooltip ?>">
            #<?= h($ev['id']) ?>
        </a>
    <?php endforeach; ?>

    <?php if ($overflow > 0): ?>
        <span class="badge bg-secondary text-white related-event-toggle"
              style="cursor:pointer;"
              title="<?= __('Show %d more', $overflow) ?>"
              data-overflow="<?= $overflow ?>"
              onclick="
                var btn = this;
                var extras = btn.closest('.d-flex').querySelectorAll('.related-event-extra');
                var isHidden = extras[0].classList.contains('d-none');
                extras.forEach(function(el){ el.classList.toggle('d-none', !isHidden); });
                btn.textContent = isHidden ? '−' : '+' + btn.dataset.overflow;
                btn.title = isHidden ? '<?= __('Collapse') ?>' : '<?= __('Show %d more', $overflow) ?>';
              ">
            +<?= $overflow ?>
        </span>
    <?php endif; ?>

    <?php if ($attribute && !empty($attribute['value'])): ?>
        <a href="<?= $baseurl ?>/attributes/search/value:<?= urlencode($attribute['value']) ?>"
           class="text-secondary ms-1"
           title="<?= __('Search for this value') ?>"
           aria-label="<?= __('Search for this value') ?>">
            <i class="fas fa-search" style="font-size:.8em;"></i>
        </a>
    <?php endif; ?>
</div>