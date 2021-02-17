<?php
$objectId = intval($object['id']);
$html = '';
if (isset($sightingsData['data'][$objectId])) {
    $objectSighting = $sightingsData['data'][$objectId];
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
  <?php
    if ($isAclSighting):
  ?>
      <i class="far fa-thumbs-up useCursorPointer" title="<?php echo __('Add sighting');?>" role="button" tabindex="0" aria-label="<?php echo __('Add sighting');?>" onmouseover="flexibleAddSighting(this, '0', '<?= $objectId ?>', '<?php echo h($object['event_id']);?>', 'top');" onclick="addSighting('0', '<?= $objectId ?>', '<?php echo h($object['event_id']);?>');">&nbsp;</i>
      <i class="far fa-thumbs-down useCursorPointer" title="<?php echo __('Mark as false-positive');?>" role="button" tabindex="0" aria-label="<?php echo __('Mark as false-positive');?>" onmouseover="flexibleAddSighting(this, '1', '<?= $objectId ?>', '<?php echo h($object['event_id']);?>', 'bottom');" onclick="addSighting('1', '<?= $objectId ?>', '<?php echo h($object['event_id']);?>');">&nbsp;</i>
      <i class="fas fa-wrench useCursorPointer sightings_advanced_add" title="<?php echo __('Advanced sightings');?>" role="button" tabindex="0" aria-label="<?php echo __('Advanced sightings');?>" data-object-id="<?= $objectId ?>" data-object-context="attribute">&nbsp;</i>
  <?php
    endif;
  ?>
  <span id="sightingCount_<?php echo $objectId; ?>" class="bold" data-placement="top" data-toggle="popover" data-trigger="hover" data-content="<?= h($html) ?>">
    (<span class="green"><?= $s ?></span>/<span class="red"><?= $f ?></span>/<span class="orange"><?= $e ?></span>)
  </span>
</td>
<td class="short">
  <?php
    if (!empty($sightingsData['csv'][$objectId])) {
      echo $this->element('sparkline', array('scope' => 'object', 'id' => $objectId, 'csv' => $sightingsData['csv'][$objectId]));
    }
  ?>
</td>
