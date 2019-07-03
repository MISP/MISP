<?php
$i = 0;
$linkColour = ($scope == 'Attribute') ? 'red' : 'white';
$count = count($event['Related' . $scope][$object['id']]);
foreach ($event['Related' . $scope][$object['id']] as $relatedAttribute) {
  if ($i == 4 && $count > 5) {
    $expandButton = __('Show ') . ($count - 4) . __(' more...');
    echo sprintf(
      '<li class="no-side-padding correlation-expand-button useCursorPointer linkButton %s">%s</li>',
      $linkColour,
      $expandButton
    );
  }
  $relatedData = array(
    'Orgc' => !empty($orgTable[$relatedAttribute['org_id']]) ? $orgTable[$relatedAttribute['org_id']] : 'N/A',
    'Date' => isset($relatedAttribute['date']) ? $relatedAttribute['date'] : 'N/A',
    'Info' => $relatedAttribute['info'],
    'Correlating Value' => $relatedAttribute['value']
  );
  $popover = '';
  foreach ($relatedData as $k => $v) {
    $popover .= '<span class=\'bold black\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
  }
  $link = $this->Html->link(
    $relatedAttribute['id'],
    array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']),
    array('class' => ($relatedAttribute['org_id'] == $me['org_id']) ? $linkColour : 'blue')
  );
  echo sprintf(
    '<li class="no-side-padding %s" %s data-toggle="popover" data-content="%s" data-trigger="hover">%s&nbsp;</li>',
    ($i > 4 || $i == 4 && $count > 5) ? 'correlation-expanded-area' : '',
    ($i > 4 || $i == 4 && $count > 5) ? 'style="display:none;"' : '',
    h($popover),
    $link
  );

  $i++;
}
if ($i > 5) {
  echo sprintf(
    '<li class="no-side-padding correlation-collapse-button useCursorPointer linkButton %s" style="display:none;">%s</li>',
    $linkColour,
    __('Collapse…')
  );
}
?>
