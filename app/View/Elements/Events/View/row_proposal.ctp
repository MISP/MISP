<?php
  $tr_class = 'darkOrangeRow';
  $linkClass = 'white';
  $currentType = 'denyForm';
  if (!empty($objectContainer)) {
    if (!empty($child)) {
      if ($child === 'last') {
        $tr_class .= ' tableInsetOrangeLast';
      } else {
        $tr_class .= ' tableInsetOrangeMiddle';
      }
    } else {
      $tr_class .= ' tableInsetOrange';
    }
    if ($objectContainer === true) {
      $tr_class .= ' tableHighlightBorderCenter borderBlue';
    } else {
      $tr_class .= ' tableHighlightBorderBottom borderBlue';
    }
  } else {
    if (!empty($child)) {
      if ($child === 'last') {
        $tr_class .= ' tableHighlightBorderBottom borderOrange';
      } else {
        $tr_class .= ' tableHighlightBorderCenter borderOrange';
      }
    } else {
      $tr_class .= ' tableHighlightBorder borderOrange';
    }
  }
?>
<tr id = "proposal<?php echo '_' . $object['id'] . '_tr'; ?>" class="<?php echo $tr_class; ?>">
  <?php if ($mayModify): ?>
    <td style="width:10px;" data-position="<?php echo h($object['objectType']) . '_' . h($object['id']); ?>">
      <input id = "select_proposal_<?php echo $object['id']; ?>" class="select_proposal row_checkbox" type="checkbox" data-id="<?php echo $object['id'];?>" />
    </td>
  <?php endif; ?>
    <td class="short context hidden">
      <?php
        echo $object['objectType'] == 0 ? h($object['id']) : '&nbsp;';
      ?>
    </td>
    <td class="short context hidden">
      <?php echo $object['objectType'] == 0 ? h($object['uuid']) : '&nbsp;'; ?>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_timestamp_solid'; ?>">
        <?php
          if (isset($object['timestamp'])) echo date('Y-m-d', $object['timestamp']);
          else echo '&nbsp';
        ?>
      </div>
    </td>
    <td class="short">
  <?php
    if ($object['objectType'] != 0) {
      if (isset($object['Org']['name'])) {
        $imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . 'orgs' . DS . h($object['Org']['name']) . '.png';
        if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($object['Org']['name']) . '.png', array('alt' => h($object['Org']['name']), 'title' => h($object['Org']['name']), 'style' => 'width:24px; height:24px'));
        else echo h($object['Org']['name']);
      }
    } else { ?>
    &nbsp;
  <?php
    }
  ?>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_category_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_category_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'category', <?php echo $event['Event']['id'];?>);">
        <?php echo h($object['category']); ?>
      </div>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_type_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_type_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'type', <?php echo $event['Event']['id'];?>);">
        <?php echo h($object['type']); ?>
      </div>
    </td>
    <td id="<?php echo h($currentType) . '_' . h($object['id']) . '_container'; ?>" class="showspaces limitedWidth shortish">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_value_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <?php
        if ('attachment' !== $object['type'] && 'malware-sample' !== $object['type']) $editable = ' ondblclick="activateField(\'' . $currentType . '\', \'' . $object['id'] . '\', \'value\', \'' . $event['Event']['id'] . '\');"';
        else $editable = '';
      ?>
      <div id = "<?php echo $currentType; ?>_<?php echo $object['id']; ?>_value_solid" class="inline-field-solid" <?php echo $editable; ?>>
        <span <?php if (Configure::read('Plugin.Enrichment_hover_enable') && isset($modules) && isset($modules['hover_type'][$object['type']])) echo 'class="eventViewAttributeHover" data-object-type="' . h($currentType) . '" data-object-id="' . h($object['id']) . '"'?>>
          <?php
            $sigDisplay = $object['value'];
            if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ) {
              if ($object['type'] == 'attachment' && isset($object['image'])) {
                $extension = explode('.', $object['value']);
                $extension = end($extension);
                $uri = 'data:image/' . strtolower(h($extension)) . ';base64,' . h($object['image']);
                echo '<img class="screenshot screenshot-collapsed useCursorPointer" src="' . $uri . '" title="' . h($object['value']) . '" />';
              } else {
                $t = ($object['objectType'] == 0 ? 'attributes' : 'shadow_attributes');
                $filenameHash = explode('|', nl2br(h($object['value'])));
                if (strrpos($filenameHash[0], '\\')) {
                  $filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
                  $filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
                  echo h($filepath);
                  echo '<a href="' . $baseurl . '/' . h($t) . '/download/' . h($object['id']) . '" class="' . $linkClass . '">' . h($filename) . '</a>';
                } else {
                  echo '<a href="' . $baseurl . '/' . h($t) . '/download/' . h($object['id']) . '" class="' . $linkClass . '">' . h($filenameHash[0]) . '</a>';
                }
                if (isset($filenameHash[1])) echo '<br />' . $filenameHash[1];
              }
            } else if (strpos($object['type'], '|') !== false) {
              $filenameHash = explode('|', $object['value']);
              echo h($filenameHash[0]);
              if (isset($filenameHash[1])) {
                $separator = '<br />';
                if (in_array($object['type'], array('ip-dst|port', 'ip-src|port'))) {
                  $separator = ':';
                }
                echo $separator . h($filenameHash[1]);
              }
            } else if ('vulnerability' == $object['type']) {
              if (! is_null(Configure::read('MISP.cveurl'))) {
                $cveUrl = Configure::read('MISP.cveurl');
              } else {
                $cveUrl = "http://www.google.com/search?q=";
              }
              echo $this->Html->link($sigDisplay, $cveUrl . $sigDisplay, array('target' => '_blank', 'class' => $linkClass));
            } else if ('link' == $object['type']) {
              echo $this->Html->link($sigDisplay, $sigDisplay, array('class' => $linkClass));
            } else if ('cortex' == $object['type']) {
              echo '<div class="cortex-json" data-cortex-json="' . h($object['value']) . '">Cortex object</div>';
            } else if ('text' == $object['type']) {
              if ($object['category'] == 'External analysis' && preg_match('/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i', $object['value'])) {
                echo '<a href="' . $baseurl . '/events/view/' . h($object['value']) . '" class="' . $linkClass . '">' . h($object['value']) . '</a>';
              } else {
                $sigDisplay = str_replace("\r", '', h($sigDisplay));
                $sigDisplay = str_replace(" ", '&nbsp;', $sigDisplay);
                echo nl2br($sigDisplay);
              }
            } else if ('hex' == $object['type']) {
              $sigDisplay = str_replace("\r", '', $sigDisplay);
              echo '<span class="hex-value" title="Hexadecimal representation">' . nl2br(h($sigDisplay)) . '</span>&nbsp;<span role="button" tabindex="0" aria-label="Switch to binary representation" class="icon-repeat hex-value-convert useCursorPointer" title="Switch to binary representation"></span>';
            } else {
              $sigDisplay = str_replace("\r", '', $sigDisplay);
              echo nl2br(h($sigDisplay));
            }
            if (isset($object['validationIssue'])) echo ' <span class="icon-warning-sign" title="Warning, this doesn\'t seem to be a legitimage ' . strtoupper(h($object['type'])) . ' value">&nbsp;</span>';
          ?>
        </span>
        <?php
          if (isset($object['warnings'])) {
            $temp = '';
            $components = array(1 => 0, 2 => 1);
            $valueParts = explode('|', $object['value']);
            foreach ($components as $component => $valuePart) {
              if (isset($object['warnings'][$component]) && isset($valueParts[$valuePart])) {
                foreach ($object['warnings'][$component] as $warning) $temp .= '<span class=\'bold\'>' . h($valueParts[$valuePart]) . '</span>: <span class=\'red\'>' . h($warning) . '</span><br />';
              }
            }
            echo ' <span class="icon-warning-sign" data-placement="right" data-toggle="popover" data-content="' . h($temp) . '" data-trigger="hover">&nbsp;</span>';
          }
        ?>
      </div>
    </td>
    <td class="shortish">
      <?php
        if ($object['objectType'] == 0):
      ?>
        <div class="attributeTagContainer">
          &nbsp;
        </div>
      <?php
        else:
      ?>
        &nbsp;
      <?php
        endif;
      ?>
    </td>
    <td class="showspaces bitwider">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_comment_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'comment', <?php echo $event['Event']['id'];?>);">
        <?php echo nl2br(h($object['comment'])); ?>&nbsp;
      </div>
    </td>
    <td class="short" style="padding-top:3px;">&nbsp;</td>
    <td class="shortish">
      <ul class="inline" style="margin:0px;">
        <?php
          if ($object['objectType'] == 0) {
            $relatedObject = 'Attribute';
            $otherColour = !empty($object['ShadowAttribute']) ? 'blue' : 'white';
          } else {
            $relatedObject = 'ShadowAttribute';
            $otherColour = 'white';
          }
          $relatedObject = $object['objectType'] == 0 ? 'Attribute' : 'ShadowAttribute';

          if (!empty($event['Related' . $relatedObject][$object['id']])) {
            foreach ($event['Related' . $relatedObject][$object['id']] as $relatedAttribute) {
              $relatedData = array('Event info' => $relatedAttribute['info'], 'Correlating Value' => $relatedAttribute['value'], 'date' => isset($relatedAttribute['date']) ? $relatedAttribute['date'] : 'N/A');
              $popover = '';
              foreach ($relatedData as $k => $v) {
                $popover .= '<span class=\'bold black\'>' . h($k) . '</span>: <span class="blue">' . h($v) . '</span><br />';
              }
              echo '<li style="padding-right: 0px; padding-left:0px;" data-toggle="popover" data-content="' . h($popover) . '" data-trigger="hover"><span>';
              if ($relatedAttribute['org_id'] == $me['org_id']) {
                echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']), array('class' => 'red'));
              } else {
                echo $this->Html->link($relatedAttribute['id'], array('controller' => 'events', 'action' => 'view', $relatedAttribute['id'], true, $event['Event']['id']), array('class' => $otherColour));
              }
              echo "</span></li>";
              echo ' ';
            }
          }
        ?>
      </ul>
    </td>
    <td class="shortish">
      <ul class="inline" style="margin:0px;">
        <?php
          if (!empty($object['Feed'])):
            foreach ($object['Feed'] as $feed):
              $popover = '';
              foreach ($feed as $k => $v):
                if ($k == 'id') continue;
                $popover .= '<span class=\'bold black\'>' . Inflector::humanize(h($k)) . '</span>: <span class="blue">' . h($v) . '</span><br />';
              endforeach;
            ?>
              <li style="padding-right: 0px; padding-left:0px;"  data-toggle="popover" data-content="<?php echo h($popover);?>" data-trigger="hover"><span>
                <?php
                  if ($isSiteAdmin):
                    echo $this->Html->link($feed['id'], array('controller' => 'feeds', 'action' => 'previewIndex', $feed['id']), array('style' => 'margin-right:3px;'));
                  else:
                ?>
                  <span style="margin-right:3px;"><?php echo h($feed['id']);?></span>
                <?php
                  endif;
                endforeach;
                ?>
              </li>
        <?php
          endif;
        ?>
      </ul>
    </td>
    <td class="short">
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_placeholder'; ?>" class = "inline-field-placeholder"></div>
      <div id = "<?php echo $currentType . '_' . $object['id'] . '_to_ids_solid'; ?>" class="inline-field-solid" ondblclick="activateField('<?php echo $currentType; ?>', '<?php echo $object['id']; ?>', 'to_ids', <?php echo $event['Event']['id'];?>);">
        <?php
          if ($object['to_ids']) echo 'Yes';
          else echo 'No';
        ?>
      </div>
    </td>
    <td class="shortish">&nbsp;</td>
  <?php
    if (Configure::read('Plugin.Sightings_enable') !== false):
  ?>
  <td class="shortish">
    <span id="sightingForm_<?php echo h($object['id']);?>">
    <?php
      if ($object['objectType'] == 0):
        echo $this->Form->create('Sighting', array('id' => 'Sighting_' . $object['id'], 'url' => '/sightings/add/' . $object['id'], 'style' => 'display:none;'));
        echo $this->Form->input('type', array('label' => false, 'id' => 'Sighting_' . $object['id'] . '_type'));
        echo $this->Form->end();
    ?>
    </span>
    <?php
      $temp = array();
      if (isset($sightingsData['csv'][$object['id']])) {
        $temp = $sightingsData['csv'][$object['id']];
      }
    ?>
    <span class="icon-thumbs-up useCursorPointer" title="Add sighting" role="button" tabindex="0" aria-label="Add sighting" onClick="addSighting('0', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']);?>', '<?php echo h($page); ?>');">&nbsp;</span>
    <span class="icon-thumbs-down useCursorPointer" title="Mark as false-positive" role="button" tabindex="0" aria-label="Mark as false-positive" onClick="addSighting('1', '<?php echo h($object['id']); ?>', '<?php echo h($event['Event']['id']);?>', '<?php echo h($page); ?>');">&nbsp;</span>
    <span class="icon-wrench useCursorPointer sightings_advanced_add" title="Advanced sightings"  role="button" tabindex="0" aria-label="Advanced sightings" data-object-id="<?php echo h($object['id']); ?>" data-object-context="attribute">&nbsp;</span>
    <span id="sightingCount_<?php echo h($object['id']); ?>" class="bold sightingsCounter_<?php echo h($object['id']); ?>" data-placement="top" data-toggle="popover" data-trigger="hover" data-content="<?php echo isset($sightingsData['data'][$object['id']]['html']) ? $sightingsData['data'][$object['id']]['html'] : ''; ?>">
      <?php
        $s = (!empty($sightingsData['data'][$object['id']]['sighting']['count']) ? $sightingsData['data'][$object['id']]['sighting']['count'] : 0);
        $f = (!empty($sightingsData['data'][$object['id']]['false-positive']['count']) ? $sightingsData['data'][$object['id']]['false-positive']['count'] : 0);
        $e = (!empty($sightingsData['data'][$object['id']]['expiration']['count']) ? $sightingsData['data'][$object['id']]['expiration']['count'] : 0);
      ?>
    </span>
    <span id="ownSightingCount_<?php echo h($object['id']); ?>" class="bold sightingsCounter_<?php echo h($object['id']); ?>" data-placement="top" data-toggle="popover" data-trigger="hover" data-content="<?php echo isset($sightingsData['data'][$object['id']]['html']) ? $sightingsData['data'][$object['id']]['html'] : ''; ?>">
      <?php echo '(<span class="green">' . h($s) . '</span>/<span class="red">' . h($f) . '</span>/<span class="orange">' . h($e) . '</span>)'; ?>
    </span>
    <?php
      endif;
    ?>
  </td>
  <td class="short">
    <?php
      if ($object['objectType'] == 0 && !empty($temp)) {
        echo $this->element('sparkline', array('id' => $object['id'], 'csv' => $temp));
      }
    ?>
  </td>
  <?php
    endif;
  ?>
  <td class="short action-links">
    <?php
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin) {
          echo $this->Form->create('Shadow_Attribute', array('id' => 'ShadowAttribute_' . $object['id'] . '_accept', 'url' => '/shadow_attributes/accept/' . $object['id'], 'style' => 'display:none;'));
          echo $this->Form->end();
        ?>
          <span class="icon-ok useCursorPointer" title="Accept Proposal" role="button" tabindex="0" aria-label="Accept proposal" onClick="acceptObject('shadow_attributes', '<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
        <?php
        }
        if (($event['Orgc']['id'] == $me['org_id'] && $mayModify) || $isSiteAdmin || ($object['org_id'] == $me['org_id'])) {
        ?>
          <span class="icon-trash useCursorPointer" title="Discard proposal" role="button" tabindex="0" aria-label="Discard proposal" onClick="deleteObject('shadow_attributes', 'discard' ,'<?php echo $object['id']; ?>', '<?php echo $event['Event']['id']; ?>');"></span>
        <?php
        }
    ?>
  </td>
</tr>
