<div class="info_container_form">
  <div class="bold blue"><?= __('Matched event') ?></div>
  <?php
    if (empty($event)) {
      $message = __('No matching events found.');
      if ($validUuid) {
          $message .= ' ' . __('This will still allow you to store the UUID. It will extend the assigned event as soon as it is created/becomes visible.');
      }
      echo '<div class="red bold">' . $message . '</div>';
    } else {
      $fields = array(
          'Event.id' => __('ID'),
          'Event.analysis' => __('Analysis'),
          'ThreatLevel.name' => __('Threat level'),
          'Tag' => __('Tags'),
          'Event.info' => __('Info'),
      );
      foreach ($fields as $fieldData => $field) {
        if ($fieldData === 'Tag') {
          echo '<div><span class="blue bold">Tags</span>: ';
          if (!empty($event['EventTag'])) {
            echo '<span>' . $this->element('ajaxTags', array('event' => $event, 'tags' => $event['EventTag'], 'static_tags_only' => true, 'tagAccess' => false, 'localTagAccess' => false)) . '</span>';
          }
          echo '</div>';
        } else {
          $data = Hash::extract($event, $fieldData);
          if ($fieldData === 'Event.analysis') {
            $data[0] = $analysisLevels[intval($data[0])];
          }
          if ($fieldData === 'Event.id') {
              echo '<span class="blue bold">' . $field . '</span>: <a href="' . $baseurl . '/events/view/' . $data[0] . '">' . h($data[0]) . '</a><br>';
          } else {
              echo '<span class="blue bold">' . $field . '</span>: ' . h($data[0]) . '<br>';
          }
        }
      }
    }
  ?>
</div>
