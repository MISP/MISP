<div class="info_container_form">
  <div class="bold blue">Matched event</div>
  <?php
    if (empty($event)) {
      $message = __('No matching events found.');
      if ($validUuid) $message .= ' ' . __('This will still allow you to store the UUID. It will extend the assigned event as soon as it is created / becomes visible.');
      echo '<div class="red bold">' . $message . '</div>';
    } else {
      $fields = array(
        'id' => 'Event.id',
        'analysis' => 'Event.analysis',
        'threat level' => 'ThreatLevel.name',
        'tags' => 'Tag',
        'info' => 'Event.info'
      );
      foreach ($fields as $field => $fieldData) {
        if ($field == 'tags') {
          echo '<div><span class="blue bold">Tags</span>: ';
          if (!empty($event['EventTag'])) {
            echo '<span>' . $this->element('ajaxTags', array('event' => $event, 'tags' => $event['EventTag'], 'tagAccess' => false)) . '</span>';
          }
          echo '</div>';
        } else {
          $data = Hash::extract($event, $fieldData);
          if ($field == 'analysis') {
            $data[0] = $analysisLevels[intval($data[0])];
          }
          echo '<span class="blue bold">' . ucfirst($field) . '</span>: ' . h($data[0]) . '<br />';
        }
      }
    }
  ?>
</div>
