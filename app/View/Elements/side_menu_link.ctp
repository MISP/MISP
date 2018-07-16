<?php
  $a = '';
  if (!empty($element_id)) {
    $element_id = 'id="li' . $element_id . '"';
  } else {
    if (!empty($url)) {
      $urlparts = explode('/', $url);
      $element_id = 'id="li' . h(end($urlparts)) . '"';
    } else {
      $element_id = '';
    }
  }
  if (empty($url)) {
    $a = 'href="#"';
  } else {
    $a = 'href="' . $baseurl . h($url) . '"';
  }
  if (!empty($class)) {
    $class = 'class="' . h($class) . '"';
  } else {
    $class = '';
  }
  if (!empty($onClick)) {
    $params = array();
    foreach ($onClick['params'] as $param) {
      $params[] = h($param);
    }
    $params = implode('\', \'', $params);
    $a .= sprintf(' onClick="%s(\'%s\')"', $onClick['function'], $params);
  }

  echo sprintf('<li %s %s><a %s>%s</a></li>', $element_id, $class, $a, h($text));
?>
