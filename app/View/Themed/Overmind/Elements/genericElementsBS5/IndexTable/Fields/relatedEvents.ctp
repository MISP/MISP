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


$marker = '';
if (!empty($attribute['correlation_exclusion'])) {
    $marker = sprintf(
        '<span class="badge text-bg-warning text-dark d-inline-flex align-items-center gap-1"'
        . ' title="%s"><i class="fas fa-ban"></i> %s</span>',
        __('The attribute value matches a correlation exclusion rule.'),
        __('Excluded')
    );
} elseif (!empty($attribute['over_correlation'])) {
    $marker = sprintf(
        '<span class="badge text-bg-danger d-inline-flex align-items-center gap-1"'
        . ' title="%s"><i class="fas fa-exclamation-triangle"></i> %s</span>',
        __('The correlation threshold has been exceeded for this value.'),
        __('Overcorrelated')
    );
}

if (empty($relatedList)) {
    echo $marker;
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
        'org_name' => $ra['org_name'] ?? ($orgTable[$ra['org_id'] ?? 0] ?? null),
        'value' => isset($ra['value']) ? $ra['value'] : '',
        'date'  => isset($ra['date'])  ? $ra['date']  : '',
    ];
}

if (empty($events)) {
    echo $marker;
    return;
}

$maxVisible = 4;
$total      = count($events);
$overflow   = $total - $maxVisible;
?>

<div class="d-flex flex-wrap align-items-center gap-1">
    <?php foreach ($events as $i => $ev): ?>
        <?php
            $hidden = ($i >= $maxVisible && $overflow > 0);
            $isOwn = !empty($ev['org']) && isset($me['org_id']) && (int)$ev['org'] === (int)$me['org_id'];
            $facts = [
                __('Creator org') => $ev['org_name'] ?: null,
                __('Date') => $ev['date'] ?: null,
                __('Correlating value') => ($ev['value'] !== '' && $ev['value'] !== ($attribute['value'] ?? null))
                    ? $ev['value'] : null,
            ];
            $popover = (string)$ev['info'] !== '' ? '<div class="fw-semibold mb-1">' . h($ev['info']) . '</div>' : '';
            foreach (array_filter($facts) as $label => $fact) {
                $popover .= '<div class="small"><span class="text-muted">' . h($label) . ':</span> '
                    . h($fact) . '</div>';
            }
            if ($isOwn) {
                $popover .= '<div class="small text-muted mt-1"><i class="fas fa-building me-1"></i>'
                    . h(__('Your organisation')) . '</div>';
            }
        ?>
        <a href="<?= $baseurl ?>/events/view/<?= h($ev['id']) ?>"
           class="badge text-decoration-none bg-primary om-lazy-popover<?= $hidden ? ' d-none related-event-extra' : '' ?>"
           aria-label="<?= h(__('Event #%s', $ev['id'])) ?>"
           data-bs-title="<?= h(__('Event #%s', $ev['id'])) ?>"
           data-bs-content="<?= h($popover) ?>"
           data-bs-custom-class="om-corr-popover">
            <?php if ($isOwn): ?><i class="fas fa-building me-1" style="font-size:.85em;"></i><?php endif; ?>#<?= h($ev['id']) ?>
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

    <?= $marker ?>

    <?php if ($attribute && !empty($attribute['value'])): ?>
        <a href="<?= $baseurl ?>/attributes/index?value=<?= rawurlencode('"' . $attribute['value'] . '"') ?>"
           class="text-secondary ms-1"
           title="<?= __('Search for this value') ?>"
           aria-label="<?= __('Search for this value') ?>">
            <i class="fas fa-search" style="font-size:.8em;"></i>
        </a>
    <?php endif; ?>
</div>