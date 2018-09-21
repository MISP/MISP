<?php
  $sigDisplay = $object['value'];
  if ('attachment' == $object['type'] || 'malware-sample' == $object['type'] ) {
    if ($object['type'] == 'attachment' && isset($object['image'])) {
      $extension = explode('.', $object['value']);
      $extension = end($extension);
      $uri = 'data:image/' . strtolower(h($extension)) . ';base64,' . h($object['image']);
      echo '<img class="screenshot screenshot-collapsed useCursorPointer" src="' . $uri . '" title="' . h($object['value']) . '" />';
    } else {
      $filenameHash = explode('|', h($object['value']));
      if (strrpos($filenameHash[0], '\\')) {
        $filepath = substr($filenameHash[0], 0, strrpos($filenameHash[0], '\\'));
        $filename = substr($filenameHash[0], strrpos($filenameHash[0], '\\'));
        echo h($filepath);
        echo '<a href="' . $baseurl . '/attributes/download/' . h($object['id']) . '" class="' . $linkClass . '">' . h($filename) . '</a>';
      } else {
        echo '<a href="' . $baseurl . '/attributes/download/' . h($object['id']) . '" class="' . $linkClass . '">' . h($filenameHash[0]) . '</a>';
      }
      if (isset($filenameHash[1])) echo '<br />' . $filenameHash[1];
    }
  } else if (strpos($object['type'], '|') !== false) {
    $separator = in_array($object['type'], array('ip-dst|port', 'ip-src|port')) ? ':' : '<br />';
    $value_pieces = explode('|', $object['value']);
    foreach ($value_pieces as $k => $v) {
      $value_pieces[$k] = h($v);
    }
    $object['value'] = implode($separator, $value_pieces);
    echo ($object['value']);
  } else if ('vulnerability' == $object['type']) {
    $cveUrl = (is_null(Configure::read('MISP.cveurl'))) ? "http://www.google.com/search?q=" : Configure::read('MISP.cveurl');
    echo $this->Html->link($sigDisplay, $cveUrl . $sigDisplay, array('target' => '_blank', 'class' => $linkClass));
  } else if ('link' == $object['type']) {
    echo $this->Html->link($sigDisplay, $sigDisplay, array('class' => $linkClass));
  } else if ('cortex' == $object['type']) {
    echo '<div class="cortex-json" data-cortex-json="' . h($object['value']) . '">Cortex object</div>';
  } else if ('text' == $object['type']) {
    if (($object['category'] == 'Internal reference' || $object['category'] == 'External analysis') && preg_match('/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i', $object['value'])) {
      echo '<a href="' . $baseurl . '/events/view/' . h($object['value']) . '" class="' . $linkClass . '">' . h($object['value']) . '</a>';
    } else {
      $sigDisplay = str_replace("\r", '', h($sigDisplay));
      $sigDisplay = str_replace(" ", '&nbsp;', $sigDisplay);
      echo $sigDisplay;
    }
  } else if ('hex' == $object['type']) {
    $sigDisplay = str_replace("\r", '', $sigDisplay);
    echo '<span class="hex-value" title="' . __('Hexadecimal representation') . '">' . h($sigDisplay) . '</span>&nbsp;<span role="button" tabindex="0" aria-label="' . __('Switch to binary representation') . '" class="icon-repeat hex-value-convert useCursorPointer" title="' . __('Switch to binary representation') . '"></span>';
  } else {
    $sigDisplay = str_replace("\r", '', $sigDisplay);
    echo h($sigDisplay);
  }
  if (isset($object['validationIssue'])) echo ' <span class="icon-warning-sign" title="' . __('Warning, this doesn\'t seem to be a legitimate ') . strtoupper(h($object['type'])) . __(' value') . '">&nbsp;</span>';
?>
