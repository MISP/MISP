<?php
$objectId = intval($object['id']);
$html = '';
$objectSighting = $sightingsData['data'][$objectId] ?? [];
// What each SightingDB has counted, as one more source of sightings and false-positives
foreach ($object['Sightingdb'] ?? [] as $hit) {
    $source = $sightingdbs[$hit['sightingdb_id']]['Sightingdb']['name'] ?? __('SightingDB');
    if (stripos($source, 'sightingdb') === false) {
        $source .= ' (SightingDB)';
    }
    $counts = [
        'sighting' => empty($hit['count']) ? null : $hit,
        'false-positive' => $hit['false_positive'] ?? null,
    ];
    foreach ($counts as $type => $typeHit) {
        if (empty($typeHit['count'])) {
            continue;
        }
        if (!isset($objectSighting[$type])) {
            $objectSighting[$type] = ['count' => 0, 'orgs' => []];
        }
        $objectSighting[$type]['count'] += $typeHit['count'];
        $objectSighting[$type]['orgs'][$source] = ['count' => $typeHit['count'], 'date' => $typeHit['last_seen']];
    }
    // A TTL is SightingDB's word for when a value stops being valid, as an org's expiration is MISP's
    if (!empty($hit['expiration'])) {
        if (!isset($objectSighting['expiration'])) {
            $objectSighting['expiration'] = ['count' => 0, 'orgs' => []];
        }
        $objectSighting['expiration']['count'] += 1;
        $objectSighting['expiration']['orgs'][$source] = ['count' => 1, 'date' => $hit['expiration']];
    }
}
if (!empty($objectSighting)) {
    foreach ($objectSighting as $type => $typeData) {
        $name = $type !== 'expiration' ? Inflector::pluralize($type) : $type;
        $html .= '<span class="blue bold">' . ucfirst(h($name)) . '</span><br>';
        foreach ($typeData['orgs'] as $org => $orgData) {
            $extra = $org === $me['Organisation']['name'] ? ' class="bold"' : "";
            if ($type == 'expiration') {
                $html .= '<span' . $extra . '>' . h($org) . '</span>: <span class="orange bold">' . $this->Time->time($orgData['date']) . '</span><br>';
            } else {
                $html .= '<span' . $extra . '>' . h($org) . '</span>: <span class="' . ($type === 'sighting' ? 'green' : 'red') . ' bold">' . h($orgData['count']) . ' (' . $this->Time->time($orgData['date']) . ')</span><br>';
            }
        }
    }

    $s = isset($objectSighting['sighting']['count']) ? intval($objectSighting['sighting']['count']) : 0;
    $f = isset($objectSighting['false-positive']['count']) ? intval($objectSighting['false-positive']['count']) : 0;
    $e = isset($objectSighting['expiration']['count']) ? intval($objectSighting['expiration']['count']) : 0;
} else {
    $s = $f = $e = 0;
}
?>
<td class="shortish">
  <?php if ($isAclSighting): ?>
      <i class="far fa-thumbs-up useCursorPointer" title="<?php echo __('Add sighting');?>" role="button" tabindex="0" aria-label="<?php echo __('Add sighting');?>" onmouseover="flexibleAddSighting(this, 0, <?= $objectId ?>, 'top');" onclick="addSighting(0, <?= $objectId ?>)"></i>
      <i class="far fa-thumbs-down useCursorPointer" title="<?php echo __('Mark as false-positive');?>" role="button" tabindex="0" aria-label="<?php echo __('Mark as false-positive');?>" onmouseover="flexibleAddSighting(this, 1, <?= $objectId ?>, 'bottom');" onclick="addSighting(1, <?= $objectId ?>)"></i>
      <i class="fas fa-wrench useCursorPointer sightings_advanced_add" title="<?php echo __('Advanced sightings');?>" role="button" tabindex="0" aria-label="<?php echo __('Advanced sightings');?>" data-object-id="<?= $objectId ?>" data-object-context="attribute"></i>
  <?php endif; ?>
  <b id="sightingCount_<?php echo $objectId; ?>" data-placement="top" data-toggle="popover" data-trigger="hover" data-content="<?= h($html) ?>">
    (<span class="green"><?= $s ?></span>/<span class="red"><?= $f ?></span>/<span class="orange"><?= $e ?></span>)
  </b>
</td>
<td class="short">
  <?php
    if (!empty($sightingsData['csv'][$objectId])) {
      echo $this->element('sparkline_new', array('scope' => 'object', 'id' => $objectId, 'csv' => $sightingsData['csv'][$objectId]));
    }
  ?>
</td>
